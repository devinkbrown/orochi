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
const x509_selfsign = @import("x509_selfsign.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");

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
    /// drives the SFU SRTP contexts from this), else null.
    pub fn exportedKeys(self: *const Terminator, addr: TransportAddress) ?dtls_srtp.ExportedKeys {
        const s = self.find(addr) orelse return null;
        if (s.state != .established) return null;
        return s.srtp_keys;
    }

    /// The negotiated SRTP profile for `addr` once established, else null.
    pub fn srtpProfile(self: *const Terminator, addr: TransportAddress) ?u16 {
        const s = self.find(addr) orelse return null;
        if (s.state != .established) return null;
        return s.srtp_profile;
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
            .client_key_exchange => self.onClientKeyExchange(addr, dh.hdr.message_seq, body, now_ms),
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
        // ServerHelloDone (msg_seq 4, empty)
        {
            feedTranscript(&s.transcript, .server_hello_done, server_hello_seq + 3, &.{});
            total += framePlaintextHandshake(out[total..], .server_hello_done, server_hello_seq + 3, 0, s.epoch0_write_seq, &.{}) catch return null;
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

    fn init() ClientDriver {
        var cr: [32]u8 = undefined;
        for (&cr, 0..) |*b, i| b.* = @intCast((i *% 7) +% 1);
        return .{ .client_random = cr, .ecdhe = kx.generateKeyPair(@splat(0x5c)) };
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

test "full DTLS-SRTP loopback handshake: both sides derive identical SRTP keys" {
    var setup = try makeTerminator(0x77);
    defer testing.allocator.free(setup.sessions);
    defer setup.term.deinit();
    var term = &setup.term;
    const addr = testAddr(5, 7000);

    var client = ClientDriver.init();
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
    feedTranscript(&client.transcript, .client_hello, 1, ch2_body);
    var ch2_dg: [700]u8 = undefined;
    const ch2_len = try framePlaintextHandshake(&ch2_dg, .client_hello, 1, 0, 1, ch2_body);
    const flight4 = term.handleDatagram(addr, ch2_dg[0..ch2_len], 101, &out) orelse return error.TestUnexpectedResult;

    // 3) Parse flight 4: ServerHello, Certificate, ServerKeyExchange, ServerHelloDone.
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
                    feedTranscript(&client.transcript, .server_hello, hh.hdr.message_seq, mbody);
                },
                .certificate => {
                    cert_der = try msg.parseCertificate(mbody);
                    feedTranscript(&client.transcript, .certificate, hh.hdr.message_seq, mbody);
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
                    feedTranscript(&client.transcript, .server_key_exchange, hh.hdr.message_seq, mbody);
                },
                .server_hello_done => {
                    feedTranscript(&client.transcript, .server_hello_done, hh.hdr.message_seq, mbody);
                },
                else => return error.TestUnexpectedResult,
            }
        }
        try testing.expect(cert_der.len > 0);
        try testing.expectEqualSlices(u8, term.certDer(), cert_der);
    }

    // 4) Client derives the shared secret, master secret, and key block.
    const pre_master = try kx.computeSharedSecret(client.ecdhe.secret, client.server_point);
    client.master_secret = kx.masterSecret(&pre_master, client.client_random, client.server_random);
    client.key_block = msg.deriveKeyBlock(&client.master_secret, client.client_random, client.server_random);

    // 5) Build flight 5: ClientKeyExchange + ChangeCipherSpec + Finished.
    var flight5: [512]u8 = undefined;
    var f5_len: usize = 0;
    {
        // ClientKeyExchange (msg_seq 2, epoch0 seq 2).
        var cke_body: [80]u8 = undefined;
        const cke = try msg.buildClientKeyExchange(&cke_body, client.ecdhe.public);
        feedTranscript(&client.transcript, .client_key_exchange, 2, cke);
        f5_len += try framePlaintextHandshake(flight5[f5_len..], .client_key_exchange, 2, 0, 2, cke);

        // ChangeCipherSpec (epoch0 seq 3).
        f5_len += (try record.writePlaintext(.change_cipher_spec, 0, 3, &.{0x01}, flight5[f5_len..])).len;

        // Finished (encrypted, epoch1 seq0, msg_seq 3). verify_data over the
        // transcript up to (and including) ClientKeyExchange.
        const client_hash = client.transcript.peek();
        const client_vd = kx.verifyData(&client.master_secret, "client finished", client_hash);
        f5_len += try frameEncryptedHandshake(
            flight5[f5_len..],
            client.key_block.client_write_key,
            client.key_block.client_write_iv,
            1,
            0,
            .finished,
            3,
            &client_vd,
        );
        // The client's transcript for verifying the server's Finished includes
        // its own Finished message.
        feedTranscript(&client.transcript, .finished, 3, &client_vd);
    }

    const flight6 = term.handleDatagram(addr, flight5[0..f5_len], 102, &out) orelse return error.TestUnexpectedResult;

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
