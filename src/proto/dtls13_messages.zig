// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! DTLS 1.3 handshake *message body* codecs (RFC 9147 + RFC 8446) for the
//! TLS_AES_128_GCM_SHA256 / secp256r1 profile a WebRTC DTLS 1.3 peer negotiates.
//!
//! These build and parse the message bodies only; the 12-byte DTLS handshake
//! headers + fragmentation live in `dtls_handshake.zig`, epoch-0 plaintext
//! record framing in `dtls12_record.zig`, and epoch-2 AEAD framing in
//! `dtls_record.zig`. The state machine + key schedule live in
//! `dtls13_server.zig`.
//!
//! Unlike the DTLS 1.2 codecs (`dtls12_messages.zig`), the DTLS 1.3 ClientHello
//! carries the return-routability cookie in the TLS 1.3 `cookie` *extension*
//! (0x002c) inside the second ClientHello — not the legacy HelloVerifyRequest
//! `cookie` field, which is empty in DTLS 1.3. `use_srtp` is negotiated in
//! EncryptedExtensions (a TLS 1.3 server may not place it in ServerHello).
//!
//! Every parser is bounds-checked and fail-closed: hostile UDP input yields an
//! error, never a trap.
const std = @import("std");
const dtls_srtp = @import("dtls_srtp.zig");
const keyshare = @import("tls_keyshare.zig");

/// TLS_AES_128_GCM_SHA256 (RFC 8446 §B.4) — the WebRTC DTLS 1.3 cipher suite.
pub const cipher_tls_aes_128_gcm_sha256: u16 = 0x1301;
/// DTLS version codes (supported_versions / legacy record & ClientHello fields).
pub const dtls_version_12: u16 = 0xfefd;
pub const dtls_version_13: u16 = 0xfefc;
/// NamedGroup secp256r1 / P-256.
pub const named_group_secp256r1: u16 = 0x0017;
/// SignatureScheme ecdsa_secp256r1_sha256.
pub const sig_scheme_ecdsa_secp256r1_sha256: u16 = 0x0403;
/// SEC1 uncompressed P-256 point length (`0x04 || X32 || Y32`).
pub const p256_point_len: usize = 65;
/// SHA-256 verify_data / transcript-hash length.
pub const hash_len: usize = 32;

// Extension type codes (RFC 8446 §4.2 / RFC 5764).
pub const ext_supported_groups: u16 = 0x000a;
pub const ext_ec_point_formats: u16 = 0x000b;
pub const ext_signature_algorithms: u16 = 0x000d;
pub const ext_use_srtp: u16 = 0x000e;
pub const ext_supported_versions: u16 = 0x002b;
pub const ext_cookie: u16 = 0x002c;
pub const ext_key_share: u16 = 0x0033;
pub const ext_early_data: u16 = 0x002a;

/// The distinguished HelloRetryRequest `random` (RFC 8446 §4.1.3): the SHA-256
/// of "HelloRetryRequest". A ServerHello carrying this random IS an HRR.
pub const hello_retry_request_random = [32]u8{
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

/// TLS 1.3 CertificateVerify signature context (server side, RFC 8446 §4.4.3).
pub const cert_verify_context = "TLS 1.3, server CertificateVerify";
/// TLS 1.3 CertificateVerify signature context, CLIENT side (RFC 8446 §4.4.3) —
/// used to possession-verify a WebRTC peer's client certificate.
pub const cert_verify_context_client = "TLS 1.3, client CertificateVerify";

pub const Error = error{
    Truncated,
    BadLength,
    MissingKeyShare,
    BadPoint,
    NotClientHello,
};

// ---------------------------------------------------------------------------
// Bounded reader / writer (same idiom as dtls12_messages)
// ---------------------------------------------------------------------------

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn remaining(self: *const Reader) usize {
        return self.buf.len - self.pos;
    }
    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (self.remaining() < n) return error.Truncated;
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }
    fn readU8(self: *Reader) Error!u8 {
        return (try self.take(1))[0];
    }
    fn readU16(self: *Reader) Error!u16 {
        const s = try self.take(2);
        return std.mem.readInt(u16, s[0..2], .big);
    }
    fn readU24(self: *Reader) Error!u24 {
        const s = try self.take(3);
        return std.mem.readInt(u24, s[0..3], .big);
    }
    fn readVec8(self: *Reader) Error![]const u8 {
        return self.take(try self.readU8());
    }
    fn readVec16(self: *Reader) Error![]const u8 {
        return self.take(try self.readU16());
    }
    fn readVec24(self: *Reader) Error![]const u8 {
        return self.take(try self.readU24());
    }
};

const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn put(self: *Writer, data: []const u8) Error!void {
        if (self.buf.len - self.pos < data.len) return error.BadLength;
        @memcpy(self.buf[self.pos .. self.pos + data.len], data);
        self.pos += data.len;
    }
    fn putU8(self: *Writer, v: u8) Error!void {
        if (self.buf.len - self.pos < 1) return error.BadLength;
        self.buf[self.pos] = v;
        self.pos += 1;
    }
    fn putU16(self: *Writer, v: u16) Error!void {
        if (self.buf.len - self.pos < 2) return error.BadLength;
        std.mem.writeInt(u16, self.buf[self.pos..][0..2], v, .big);
        self.pos += 2;
    }
    fn putU24(self: *Writer, v: u24) Error!void {
        if (self.buf.len - self.pos < 3) return error.BadLength;
        std.mem.writeInt(u24, self.buf[self.pos..][0..3], v, .big);
        self.pos += 3;
    }
    fn bytes(self: *const Writer) []const u8 {
        return self.buf[0..self.pos];
    }
};

/// Locate the body of extension `ext_type` in an extension list, or null.
fn findExtension(exts: []const u8, ext_type: u16) Error!?[]const u8 {
    var r = Reader{ .buf = exts };
    while (r.remaining() >= 4) {
        const t = try r.readU16();
        const body = try r.readVec16();
        if (t == ext_type) return body;
    }
    if (r.remaining() != 0) return error.BadLength;
    return null;
}

fn writeExtensionHeader(w: *Writer, ext_type: u16, body_len: usize) Error!void {
    if (body_len > std.math.maxInt(u16)) return error.BadLength;
    try w.putU16(ext_type);
    try w.putU16(@intCast(body_len));
}

// ---------------------------------------------------------------------------
// ClientHello
// ---------------------------------------------------------------------------

pub const ClientHello13Params = struct {
    random: [32]u8,
    /// Echoed verbatim in ServerHello/HRR (empty for a native DTLS 1.3 peer).
    legacy_session_id: []const u8 = &.{},
    /// The client's secp256r1 key_share point (`0x04 || X || Y`).
    key_share_point: [p256_point_len]u8,
    srtp_profiles: []const u16,
    /// The HRR cookie to echo in the second ClientHello (empty for the first).
    cookie: []const u8 = &.{},
    /// Override the key_share list with a single arbitrary entry (test hook for
    /// the HRR group-selection path — a client that leads with a non-P-256
    /// group). When null, a single secp256r1 entry with `key_share_point`.
    key_share_override: ?keyshare.Entry = null,
    /// Whether supported_groups advertises secp256r1 (default) or x25519 (test
    /// hook for a fully P-256-less 1.3 client that must fall through to 1.2).
    advertise_secp256r1_group: bool = true,
};

/// Build a DTLS 1.3 ClientHello body offering TLS_AES_128_GCM_SHA256 over
/// secp256r1 with the extensions a WebRTC DTLS 1.3 peer needs. Used by the
/// loopback client driver.
pub fn buildClientHello13(out: []u8, params: ClientHello13Params) Error![]const u8 {
    if (params.legacy_session_id.len > 32) return error.BadLength;
    var w = Writer{ .buf = out };
    try w.putU16(dtls_version_12); // legacy_version = DTLS 1.2
    try w.put(&params.random);
    try w.putU8(@intCast(params.legacy_session_id.len));
    try w.put(params.legacy_session_id);
    try w.putU8(0); // legacy DTLS cookie: empty in DTLS 1.3
    // cipher_suites
    try w.putU16(2);
    try w.putU16(cipher_tls_aes_128_gcm_sha256);
    // compression_methods: [null]
    try w.putU8(1);
    try w.putU8(0);
    // extensions
    var ext_buf: [512]u8 = undefined;
    var ext = Writer{ .buf = &ext_buf };
    try writeSupportedVersions(&ext, &.{dtls_version_13});
    try writeSupportedGroups(&ext, params.advertise_secp256r1_group);
    try writeSignatureAlgorithms(&ext);
    if (params.key_share_override) |entry| {
        try writeKeyShareEntry(&ext, entry);
    } else {
        try writeKeyShareClient(&ext, params.key_share_point);
    }
    try writeUseSrtp(&ext, params.srtp_profiles);
    if (params.cookie.len != 0) try writeCookie(&ext, params.cookie);
    try w.putU16(@intCast(ext.pos));
    try w.put(ext.bytes());
    return w.bytes();
}

fn writeSupportedVersions(w: *Writer, versions: []const u16) Error!void {
    try writeExtensionHeader(w, ext_supported_versions, 1 + versions.len * 2);
    try w.putU8(@intCast(versions.len * 2));
    for (versions) |v| try w.putU16(v);
}

/// NamedGroup x25519 (used only as a non-P-256 group in test-hook ClientHellos).
pub const named_group_x25519: u16 = 0x001d;

fn writeSupportedGroups(w: *Writer, secp256r1: bool) Error!void {
    try writeExtensionHeader(w, ext_supported_groups, 4);
    try w.putU16(2);
    try w.putU16(if (secp256r1) named_group_secp256r1 else named_group_x25519);
}

fn writeSignatureAlgorithms(w: *Writer) Error!void {
    try writeExtensionHeader(w, ext_signature_algorithms, 4);
    try w.putU16(2);
    try w.putU16(sig_scheme_ecdsa_secp256r1_sha256);
}

fn writeKeyShareClient(w: *Writer, point: [p256_point_len]u8) Error!void {
    try writeKeyShareEntry(w, .{ .group = .secp256r1, .key_exchange = &point });
}

fn writeKeyShareEntry(w: *Writer, entry: keyshare.Entry) Error!void {
    var ks_buf: [4 + 256 + 2]u8 = undefined;
    if (entry.key_exchange.len > 256) return error.BadLength;
    const inner = keyshare.buildClientShares(&ks_buf, &.{entry}) catch return error.BadLength;
    try writeExtensionHeader(w, ext_key_share, inner.len);
    try w.put(inner);
}

fn writeUseSrtp(w: *Writer, profiles: []const u16) Error!void {
    var body: [64]u8 = undefined;
    const encoded = dtls_srtp.encodeUseSrtp(profiles, "", &body) catch return error.BadLength;
    try writeExtensionHeader(w, ext_use_srtp, encoded.len);
    try w.put(encoded);
}

fn writeCookie(w: *Writer, cookie: []const u8) Error!void {
    try writeExtensionHeader(w, ext_cookie, 2 + cookie.len);
    try w.putU16(@intCast(cookie.len));
    try w.put(cookie);
}

pub const ClientHello13View = struct {
    legacy_version: u16,
    random: [32]u8,
    /// Borrows the input; must be echoed in ServerHello/HRR.
    legacy_session_id: []const u8,
    offers_target_cipher: bool,
    offers_dtls13: bool,
    /// The secp256r1 key_share point, if the client offered one.
    key_share_point: ?[p256_point_len]u8,
    /// Whether the client listed secp256r1 in supported_groups (so we may send an
    /// HRR selecting it even when CH1's key_share led with a different group).
    offers_secp256r1_group: bool,
    /// use_srtp extension body (borrows input), empty if absent.
    use_srtp_body: []const u8,
    /// The TLS 1.3 cookie-extension value (borrows input), empty if absent.
    cookie: []const u8,
    /// Whether the client offered the `early_data` extension (rejected in CH2).
    has_early_data: bool,
};

/// Parse a DTLS 1.3 ClientHello body. Fail-closed on any structural violation.
pub fn parseClientHello13(body: []const u8) Error!ClientHello13View {
    var r = Reader{ .buf = body };
    const version = try r.readU16();
    const rand = try r.take(32);
    const session_id = try r.readVec8();
    _ = try r.readVec8(); // legacy cookie (empty in DTLS 1.3)
    const suites = try r.readVec16();
    if (suites.len % 2 != 0) return error.BadLength;
    var offers_cipher = false;
    var i: usize = 0;
    while (i + 2 <= suites.len) : (i += 2) {
        if (std.mem.readInt(u16, suites[i..][0..2], .big) == cipher_tls_aes_128_gcm_sha256) offers_cipher = true;
    }
    _ = try r.readVec8(); // compression_methods

    var offers_13 = false;
    var use_srtp_body: []const u8 = &.{};
    var cookie: []const u8 = &.{};
    var key_point: ?[p256_point_len]u8 = null;
    var early_data = false;
    var group_secp256r1 = false;
    if (r.remaining() > 0) {
        const exts = try r.readVec16();
        if (try findExtension(exts, ext_supported_versions)) |sv| {
            offers_13 = scanSupportedVersionsHas(sv, dtls_version_13) catch false;
        }
        use_srtp_body = try findExtension(exts, ext_use_srtp) orelse &.{};
        if (try findExtension(exts, ext_cookie)) |c| cookie = try parseCookieExt(c);
        if (try findExtension(exts, ext_key_share)) |ks| key_point = try scanClientKeyShareP256(ks);
        if (try findExtension(exts, ext_supported_groups)) |sg| {
            group_secp256r1 = scanNamedGroupHas(sg, named_group_secp256r1) catch false;
        }
        early_data = (try findExtension(exts, ext_early_data)) != null;
    }

    var out: ClientHello13View = .{
        .legacy_version = version,
        .random = undefined,
        .legacy_session_id = session_id,
        .offers_target_cipher = offers_cipher,
        .offers_dtls13 = offers_13,
        .key_share_point = key_point,
        .offers_secp256r1_group = group_secp256r1,
        .use_srtp_body = use_srtp_body,
        .cookie = cookie,
        .has_early_data = early_data,
    };
    @memcpy(&out.random, rand[0..32]);
    return out;
}

fn scanSupportedVersionsHas(sv: []const u8, want: u16) Error!bool {
    var r = Reader{ .buf = sv };
    const list = try r.readVec8();
    if (list.len % 2 != 0) return error.BadLength;
    var i: usize = 0;
    while (i + 2 <= list.len) : (i += 2) {
        if (std.mem.readInt(u16, list[i..][0..2], .big) == want) return true;
    }
    return false;
}

/// Scan a supported_groups body (2-byte list length + u16 group list) for `want`.
fn scanNamedGroupHas(sg: []const u8, want: u16) Error!bool {
    var r = Reader{ .buf = sg };
    const list = try r.readVec16();
    if (list.len % 2 != 0) return error.BadLength;
    var i: usize = 0;
    while (i + 2 <= list.len) : (i += 2) {
        if (std.mem.readInt(u16, list[i..][0..2], .big) == want) return true;
    }
    return false;
}

/// Find the client's secp256r1 key_share entry and return its point. Rejects a
/// wrong-length point; returns null if no secp256r1 share is present.
fn scanClientKeyShareP256(block: []const u8) Error!?[p256_point_len]u8 {
    var it = keyshare.parseClientShares(block) catch return error.BadLength;
    while (it.next() catch return error.BadLength) |entry| {
        if (entry.group == .secp256r1) {
            if (entry.key_exchange.len != p256_point_len) return error.BadPoint;
            var pt: [p256_point_len]u8 = undefined;
            @memcpy(&pt, entry.key_exchange[0..p256_point_len]);
            return pt;
        }
    }
    return null;
}

fn parseCookieExt(body: []const u8) Error![]const u8 {
    var r = Reader{ .buf = body };
    const cookie = try r.readVec16();
    if (r.remaining() != 0) return error.BadLength;
    return cookie;
}

// ---------------------------------------------------------------------------
// ServerHello / HelloRetryRequest
// ---------------------------------------------------------------------------

fn writeServerHelloPrefix(w: *Writer, random: [32]u8, legacy_session_id: []const u8) Error!void {
    if (legacy_session_id.len > 32) return error.BadLength;
    try w.putU16(dtls_version_12); // legacy_version
    try w.put(&random);
    try w.putU8(@intCast(legacy_session_id.len));
    try w.put(legacy_session_id);
    try w.putU16(cipher_tls_aes_128_gcm_sha256);
    try w.putU8(0); // legacy_compression_method
}

/// Build a ServerHello selecting TLS_AES_128_GCM_SHA256 with supported_versions
/// (0xfefc) + key_share (server's secp256r1 point).
pub fn buildServerHello13(
    out: []u8,
    server_random: [32]u8,
    legacy_session_id: []const u8,
    key_share_point: [p256_point_len]u8,
) Error![]const u8 {
    var w = Writer{ .buf = out };
    try writeServerHelloPrefix(&w, server_random, legacy_session_id);
    var ext_buf: [256]u8 = undefined;
    var ext = Writer{ .buf = &ext_buf };
    try writeExtensionHeader(&ext, ext_supported_versions, 2);
    try ext.putU16(dtls_version_13);
    var ks_buf: [4 + p256_point_len]u8 = undefined;
    const inner = keyshare.buildServerShare(&ks_buf, .{ .group = .secp256r1, .key_exchange = &key_share_point }) catch return error.BadLength;
    try writeExtensionHeader(&ext, ext_key_share, inner.len);
    try ext.put(inner);
    try w.putU16(@intCast(ext.pos));
    try w.put(ext.bytes());
    return w.bytes();
}

/// Build a HelloRetryRequest (ServerHello-form, HRR random) carrying
/// supported_versions (0xfefc), optionally a `key_share` selecting secp256r1
/// (RFC 8446 §4.1.4 group negotiation — when CH1's key_share led with another
/// group), and the return-routability cookie. Extension order is fixed so the
/// HRR is byte-reproducible when reconstructing the transcript on CH2.
pub fn buildHelloRetryRequest(
    out: []u8,
    legacy_session_id: []const u8,
    cookie: []const u8,
    include_group_selection: bool,
) Error![]const u8 {
    var w = Writer{ .buf = out };
    try writeServerHelloPrefix(&w, hello_retry_request_random, legacy_session_id);
    var ext_buf: [256]u8 = undefined;
    var ext = Writer{ .buf = &ext_buf };
    try writeExtensionHeader(&ext, ext_supported_versions, 2);
    try ext.putU16(dtls_version_13);
    if (include_group_selection) {
        // KeyShareHelloRetryRequest is a bare selected_group (RFC 8446 §4.2.8).
        try writeExtensionHeader(&ext, ext_key_share, 2);
        try ext.putU16(named_group_secp256r1);
    }
    try writeCookie(&ext, cookie);
    try w.putU16(@intCast(ext.pos));
    try w.put(ext.bytes());
    return w.bytes();
}

pub const ServerHello13View = struct {
    random: [32]u8,
    legacy_session_id: []const u8,
    cipher_suite: u16,
    selected_version: ?u16,
    /// A full server key_share point (ServerHello), if present.
    key_share_point: ?[p256_point_len]u8,
    /// The bare selected_group of an HRR `key_share` (RFC 8446 §4.2.8), if present.
    selected_group: ?u16,
    cookie: []const u8,

    pub fn isHelloRetryRequest(self: *const ServerHello13View) bool {
        return std.mem.eql(u8, &self.random, &hello_retry_request_random);
    }
};

pub fn parseServerHello13(body: []const u8) Error!ServerHello13View {
    var r = Reader{ .buf = body };
    _ = try r.readU16(); // legacy_version
    const rand = try r.take(32);
    const session_id = try r.readVec8();
    const suite = try r.readU16();
    _ = try r.readU8(); // compression

    var selected: ?u16 = null;
    var key_point: ?[p256_point_len]u8 = null;
    var sel_group: ?u16 = null;
    var cookie: []const u8 = &.{};
    if (r.remaining() > 0) {
        const exts = try r.readVec16();
        if (try findExtension(exts, ext_supported_versions)) |sv| {
            if (sv.len == 2) selected = std.mem.readInt(u16, sv[0..2], .big);
        }
        if (try findExtension(exts, ext_key_share)) |ks| {
            if (ks.len == 2) {
                // HRR KeyShareHelloRetryRequest: a bare selected_group.
                sel_group = std.mem.readInt(u16, ks[0..2], .big);
            } else {
                const entry = keyshare.parseServerShare(ks) catch return error.BadLength;
                if (entry.group == .secp256r1) {
                    if (entry.key_exchange.len != p256_point_len) return error.BadPoint;
                    var pt: [p256_point_len]u8 = undefined;
                    @memcpy(&pt, entry.key_exchange[0..p256_point_len]);
                    key_point = pt;
                }
            }
        }
        if (try findExtension(exts, ext_cookie)) |c| cookie = try parseCookieExt(c);
    }

    var out: ServerHello13View = .{
        .random = undefined,
        .legacy_session_id = session_id,
        .cipher_suite = suite,
        .selected_version = selected,
        .key_share_point = key_point,
        .selected_group = sel_group,
        .cookie = cookie,
    };
    @memcpy(&out.random, rand[0..32]);
    return out;
}

// ---------------------------------------------------------------------------
// EncryptedExtensions (use_srtp is negotiated here in TLS 1.3)
// ---------------------------------------------------------------------------

pub fn buildEncryptedExtensions(out: []u8, srtp_profile: u16) Error![]const u8 {
    var w = Writer{ .buf = out };
    var ext_buf: [64]u8 = undefined;
    var ext = Writer{ .buf = &ext_buf };
    try writeUseSrtp(&ext, &.{srtp_profile});
    try w.putU16(@intCast(ext.pos));
    try w.put(ext.bytes());
    return w.bytes();
}

/// Parse EncryptedExtensions, returning the negotiated SRTP profile (or null).
pub fn parseEncryptedExtensions(body: []const u8) Error!?u16 {
    var r = Reader{ .buf = body };
    const exts = try r.readVec16();
    if (try findExtension(exts, ext_use_srtp)) |us| {
        if (us.len >= 4) return std.mem.readInt(u16, us[2..4], .big);
    }
    return null;
}

// ---------------------------------------------------------------------------
// Certificate (TLS 1.3 form) + CertificateVerify
// ---------------------------------------------------------------------------

/// Build a TLS 1.3 Certificate body carrying the single self-signed leaf
/// `cert_der` (empty certificate_request_context, empty per-entry extensions).
pub fn buildCertificate13(out: []u8, cert_der: []const u8) Error![]const u8 {
    var w = Writer{ .buf = out };
    try w.putU8(0); // certificate_request_context: empty
    const list_len = 3 + cert_der.len + 2; // cert_len(3) + cert + ext_len(2)
    try w.putU24(@intCast(list_len));
    try w.putU24(@intCast(cert_der.len));
    try w.put(cert_der);
    try w.putU16(0); // per-entry extensions: empty
    return w.bytes();
}

/// Parse a TLS 1.3 Certificate body, returning the first (leaf) DER.
pub fn parseCertificate13(body: []const u8) Error![]const u8 {
    var r = Reader{ .buf = body };
    _ = try r.readVec8(); // certificate_request_context
    const list = try r.readVec24();
    var lr = Reader{ .buf = list };
    const cert = try lr.readVec24();
    _ = try lr.readVec16(); // per-entry extensions
    return cert;
}

/// Fill `out` with a TLS 1.3 CertificateVerify signed content (RFC 8446 §4.4.3):
/// 64 × 0x20, `context`, a 0x00 separator, then the transcript hash. Returns the
/// written slice. `context` selects server vs. client CertificateVerify.
pub fn certificateVerifyContentCtx(out: []u8, context: []const u8, transcript_hash: []const u8) Error![]const u8 {
    const total = 64 + context.len + 1 + transcript_hash.len;
    if (out.len < total) return error.BadLength;
    @memset(out[0..64], 0x20);
    @memcpy(out[64..][0..context.len], context);
    out[64 + context.len] = 0x00;
    @memcpy(out[64 + context.len + 1 ..][0..transcript_hash.len], transcript_hash);
    return out[0..total];
}

/// Server-side CertificateVerify signed content (RFC 8446 §4.4.3).
pub fn certificateVerifyContent(out: []u8, transcript_hash: []const u8) Error![]const u8 {
    return certificateVerifyContentCtx(out, cert_verify_context, transcript_hash);
}

// ---------------------------------------------------------------------------
// CertificateRequest (RFC 8446 §4.3.2) — client-certificate capture
// ---------------------------------------------------------------------------

/// Build a CertificateRequest body: an EMPTY certificate_request_context and an
/// extensions block carrying signature_algorithms (ecdsa_secp256r1_sha256). The
/// context is empty because this request is part of the main handshake (not
/// post-handshake auth). Byte-reproducible for the transcript.
pub fn buildCertificateRequest13(out: []u8) Error![]const u8 {
    var w = Writer{ .buf = out };
    try w.putU8(0); // certificate_request_context: empty
    var ext_buf: [16]u8 = undefined;
    var ext = Writer{ .buf = &ext_buf };
    try writeSignatureAlgorithms(&ext);
    try w.putU16(@intCast(ext.pos));
    try w.put(ext.bytes());
    return w.bytes();
}

pub const CertificateRequest13View = struct {
    /// certificate_request_context (borrows input); empty during the handshake.
    context: []const u8,
    /// The request lists ecdsa_secp256r1_sha256 in signature_algorithms.
    offers_ecdsa_secp256r1_sha256: bool,
};

/// Parse a CertificateRequest body (fail-closed).
pub fn parseCertificateRequest13(body: []const u8) Error!CertificateRequest13View {
    var r = Reader{ .buf = body };
    const ctx = try r.readVec8();
    const exts = try r.readVec16();
    var offers = false;
    if (try findExtension(exts, ext_signature_algorithms)) |sa| {
        var sr = Reader{ .buf = sa };
        const list = try sr.readVec16();
        if (list.len % 2 != 0) return error.BadLength;
        var i: usize = 0;
        while (i + 2 <= list.len) : (i += 2) {
            if (std.mem.readInt(u16, list[i..][0..2], .big) == sig_scheme_ecdsa_secp256r1_sha256) offers = true;
        }
    }
    return .{ .context = ctx, .offers_ecdsa_secp256r1_sha256 = offers };
}

pub fn buildCertificateVerify(out: []u8, sig_der: []const u8) Error![]const u8 {
    var w = Writer{ .buf = out };
    try w.putU16(sig_scheme_ecdsa_secp256r1_sha256);
    try w.putU16(@intCast(sig_der.len));
    try w.put(sig_der);
    return w.bytes();
}

pub const CertificateVerifyView = struct {
    scheme: u16,
    sig_der: []const u8,
};

pub fn parseCertificateVerify(body: []const u8) Error!CertificateVerifyView {
    var r = Reader{ .buf = body };
    const scheme = try r.readU16();
    const sig = try r.readVec16();
    if (r.remaining() != 0) return error.BadLength;
    return .{ .scheme = scheme, .sig_der = sig };
}

// ---------------------------------------------------------------------------
// ACK (RFC 9147 §7)
// ---------------------------------------------------------------------------

pub const RecordNumber = struct {
    epoch: u64,
    sequence_number: u64,
};

/// Encode an ACK body: `RecordNumber record_numbers<0..2^16-1>` (2-byte list
/// length + N × {epoch:u64, sequence_number:u64}). Returns the written slice.
pub fn encodeAck(record_numbers: []const RecordNumber, out: []u8) Error![]const u8 {
    const list_bytes = record_numbers.len * 16;
    if (list_bytes > std.math.maxInt(u16)) return error.BadLength;
    var w = Writer{ .buf = out };
    try w.putU16(@intCast(list_bytes));
    for (record_numbers) |rn| {
        if (w.buf.len - w.pos < 16) return error.BadLength;
        std.mem.writeInt(u64, w.buf[w.pos..][0..8], rn.epoch, .big);
        std.mem.writeInt(u64, w.buf[w.pos + 8 ..][0..8], rn.sequence_number, .big);
        w.pos += 16;
    }
    return w.bytes();
}

/// Count the RecordNumbers in an ACK body, or an error on a malformed list.
pub fn parseAckCount(body: []const u8) Error!usize {
    var r = Reader{ .buf = body };
    const list = try r.readVec16();
    if (r.remaining() != 0) return error.BadLength;
    if (list.len % 16 != 0) return error.BadLength;
    return list.len / 16;
}

/// Read the `index`-th RecordNumber from an ACK body (fail-closed).
pub fn ackRecordNumber(body: []const u8, index: usize) Error!RecordNumber {
    var r = Reader{ .buf = body };
    const list = try r.readVec16();
    if (list.len % 16 != 0) return error.BadLength;
    const off = index * 16;
    if (off + 16 > list.len) return error.Truncated;
    return .{
        .epoch = std.mem.readInt(u64, list[off..][0..8], .big),
        .sequence_number = std.mem.readInt(u64, list[off + 8 ..][0..8], .big),
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn dummyPoint(seed: u8) [p256_point_len]u8 {
    var pt: [p256_point_len]u8 = undefined;
    for (&pt, 0..) |*b, i| b.* = seed +% @as(u8, @intCast(i));
    pt[0] = 0x04;
    return pt;
}

test "ClientHello13 round-trips cipher, key_share, srtp, dtls13, cookie" {
    var rnd: [32]u8 = undefined;
    for (&rnd, 0..) |*b, i| b.* = @intCast(i);
    const pt = dummyPoint(0x40);
    var buf: [1024]u8 = undefined;
    const body = try buildClientHello13(&buf, .{
        .random = rnd,
        .key_share_point = pt,
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
        .cookie = "cook13",
    });

    const view = try parseClientHello13(body);
    try testing.expect(view.offers_target_cipher);
    try testing.expect(view.offers_dtls13);
    try testing.expectEqualSlices(u8, &rnd, &view.random);
    try testing.expectEqualSlices(u8, &pt, &(view.key_share_point orelse return error.MissingKeyShare));
    try testing.expect(dtls_srtp.offersProfile(view.use_srtp_body, dtls_srtp.profile_aes128_cm_sha1_80));
    try testing.expectEqualStrings("cook13", view.cookie);
}

test "ClientHello13 without cookie parses (empty cookie)" {
    const pt = dummyPoint(0x11);
    var buf: [1024]u8 = undefined;
    const body = try buildClientHello13(&buf, .{
        .random = @splat(3),
        .key_share_point = pt,
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
    });
    const view = try parseClientHello13(body);
    try testing.expectEqual(@as(usize, 0), view.cookie.len);
    try testing.expect(view.offers_dtls13);
}

test "ServerHello13 round-trips key_share + selected version" {
    const rnd: [32]u8 = @splat(0xAB);
    const pt = dummyPoint(0x70);
    var buf: [256]u8 = undefined;
    const body = try buildServerHello13(&buf, rnd, &.{}, pt);
    const view = try parseServerHello13(body);
    try testing.expect(!view.isHelloRetryRequest());
    try testing.expectEqual(@as(?u16, dtls_version_13), view.selected_version);
    try testing.expectEqual(cipher_tls_aes_128_gcm_sha256, view.cipher_suite);
    try testing.expectEqualSlices(u8, &pt, &(view.key_share_point orelse return error.MissingKeyShare));
}

test "HelloRetryRequest carries the HRR random + cookie" {
    var buf: [256]u8 = undefined;
    const body = try buildHelloRetryRequest(&buf, &.{}, "the-cookie-bytes", false);
    const view = try parseServerHello13(body);
    try testing.expect(view.isHelloRetryRequest());
    try testing.expectEqual(@as(?u16, dtls_version_13), view.selected_version);
    try testing.expectEqual(@as(?u16, null), view.selected_group);
    try testing.expectEqualStrings("the-cookie-bytes", view.cookie);
}

test "HelloRetryRequest with group selection carries the selected secp256r1 group" {
    var buf: [256]u8 = undefined;
    const body = try buildHelloRetryRequest(&buf, &.{}, "cookie", true);
    const view = try parseServerHello13(body);
    try testing.expect(view.isHelloRetryRequest());
    try testing.expectEqual(@as(?u16, named_group_secp256r1), view.selected_group);
    try testing.expectEqualStrings("cookie", view.cookie);
}

test "ClientHello13 leading with a non-P-256 key_share still advertises the group" {
    const x25519_share: [32]u8 = @splat(0x09);
    var buf: [1024]u8 = undefined;
    const body = try buildClientHello13(&buf, .{
        .random = @splat(5),
        .key_share_point = undefined, // overridden below
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
        .key_share_override = .{ .group = .x25519, .key_exchange = &x25519_share },
    });
    const view = try parseClientHello13(body);
    try testing.expect(view.offers_dtls13);
    try testing.expect(view.key_share_point == null); // no secp256r1 share
    try testing.expect(view.offers_secp256r1_group); // but supports the group
}

test "EncryptedExtensions round-trips the SRTP profile" {
    var buf: [64]u8 = undefined;
    const body = try buildEncryptedExtensions(&buf, dtls_srtp.profile_aes128_cm_sha1_80);
    try testing.expectEqual(@as(?u16, dtls_srtp.profile_aes128_cm_sha1_80), try parseEncryptedExtensions(body));
}

test "Certificate13 round-trips the leaf DER" {
    const cert = "\x30\x82\x01\x00 fake-der-bytes-1.3";
    var buf: [128]u8 = undefined;
    const body = try buildCertificate13(&buf, cert);
    try testing.expectEqualSlices(u8, cert, try parseCertificate13(body));
}

test "CertificateVerify content + body round-trip" {
    var th: [hash_len]u8 = undefined;
    for (&th, 0..) |*b, i| b.* = @intCast(i +% 1);
    var content_buf: [200]u8 = undefined;
    const content = try certificateVerifyContent(&content_buf, &th);
    try testing.expectEqual(@as(usize, 64 + cert_verify_context.len + 1 + hash_len), content.len);
    try testing.expectEqual(@as(u8, 0x20), content[0]);
    try testing.expectEqual(@as(u8, 0x00), content[64 + cert_verify_context.len]);

    const sig = "\x30\x44 der-ecdsa-sig";
    var buf: [128]u8 = undefined;
    const cv = try buildCertificateVerify(&buf, sig);
    const view = try parseCertificateVerify(cv);
    try testing.expectEqual(sig_scheme_ecdsa_secp256r1_sha256, view.scheme);
    try testing.expectEqualSlices(u8, sig, view.sig_der);
}

test "CertificateRequest13 round-trips empty context + secp256r1 sig alg" {
    var buf: [32]u8 = undefined;
    const body = try buildCertificateRequest13(&buf);
    const view = try parseCertificateRequest13(body);
    try testing.expectEqual(@as(usize, 0), view.context.len);
    try testing.expect(view.offers_ecdsa_secp256r1_sha256);
}

test "certificateVerifyContentCtx differs between client and server context" {
    var th: [hash_len]u8 = @splat(0x5a);
    var sbuf: [200]u8 = undefined;
    var cbuf: [200]u8 = undefined;
    const s = try certificateVerifyContentCtx(&sbuf, cert_verify_context, &th);
    const c = try certificateVerifyContentCtx(&cbuf, cert_verify_context_client, &th);
    try testing.expect(!std.mem.eql(u8, s, c)); // context string binds the direction
    // Both share the 64-space prefix and the trailing transcript hash.
    try testing.expectEqual(@as(u8, 0x20), c[0]);
    try testing.expectEqualSlices(u8, &th, c[c.len - hash_len ..]);
}

test "ACK encode / parse round-trip" {
    const rns = [_]RecordNumber{
        .{ .epoch = 2, .sequence_number = 0 },
        .{ .epoch = 2, .sequence_number = 1 },
    };
    var buf: [64]u8 = undefined;
    const body = try encodeAck(&rns, &buf);
    try testing.expectEqual(@as(usize, 2), try parseAckCount(body));
    const rn1 = try ackRecordNumber(body, 1);
    try testing.expectEqual(@as(u64, 2), rn1.epoch);
    try testing.expectEqual(@as(u64, 1), rn1.sequence_number);
    try testing.expectError(error.Truncated, ackRecordNumber(body, 2));
}

test "parsers reject truncated / malformed input" {
    try testing.expectError(error.Truncated, parseClientHello13(&.{ 0xfe, 0xfd }));
    try testing.expectError(error.Truncated, parseServerHello13(&.{0x00}));
    try testing.expectError(error.Truncated, parseCertificate13(&.{ 0x00, 0x00 }));
    try testing.expectError(error.Truncated, parseCertificateVerify(&.{0x04}));
    try testing.expectError(error.BadLength, parseAckCount(&.{ 0x00, 0x03, 0x01, 0x02, 0x03 }));
}
