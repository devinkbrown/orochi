// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! DTLS 1.2 handshake *message body* codecs for the ECDHE-ECDSA-AES128-GCM
//! cipher suite that WebRTC endpoints negotiate (RFC 8827). These build and
//! parse the message bodies only; the 12-byte DTLS handshake headers and
//! fragmentation live in `dtls_handshake.zig`, and record framing in
//! `dtls12_record.zig`.
//!
//! Also derives the TLS 1.2 AES-128-GCM key block (RFC 5246 §6.3) from the
//! master secret.
//!
//! Every parser is bounds-checked and fail-closed: hostile UDP input yields an
//! error, never a trap.
const std = @import("std");
const dtls_srtp = @import("dtls_srtp.zig");

/// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (RFC 5289). WebRTC-mandatory.
pub const cipher_ecdhe_ecdsa_aes128_gcm_sha256: u16 = 0xc02b;
/// NamedCurve secp256r1 / P-256 (RFC 8422).
pub const named_curve_secp256r1: u16 = 0x0017;
/// ECCurveType named_curve.
pub const ec_curve_type_named: u8 = 3;
/// EC point format: uncompressed.
pub const ec_point_uncompressed: u8 = 0;
/// SignatureScheme ecdsa_secp256r1_sha256 (hash sha256(4), sig ecdsa(3)).
pub const sig_scheme_ecdsa_secp256r1_sha256: u16 = 0x0403;
/// SEC1 uncompressed P-256 point length (`0x04 || X32 || Y32`).
pub const p256_point_len: usize = 65;

// Extension type codes (RFC 8422 / RFC 5764).
pub const ext_supported_groups: u16 = 0x000a;
pub const ext_ec_point_formats: u16 = 0x000b;
pub const ext_signature_algorithms: u16 = 0x000d;
pub const ext_use_srtp: u16 = 0x000e;

pub const Error = error{
    Truncated,
    BadLength,
    UnexpectedCipherSuite,
    MissingPoint,
    BadPoint,
};

// ---------------------------------------------------------------------------
// Bounded reader
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
        const s = try self.take(1);
        return s[0];
    }

    fn readU16(self: *Reader) Error!u16 {
        const s = try self.take(2);
        return std.mem.readInt(u16, s[0..2], .big);
    }

    fn readU24(self: *Reader) Error!u24 {
        const s = try self.take(3);
        return std.mem.readInt(u24, s[0..3], .big);
    }

    /// Read an 8-bit-length-prefixed vector.
    fn readVec8(self: *Reader) Error![]const u8 {
        const n = try self.readU8();
        return self.take(n);
    }

    /// Read a 16-bit-length-prefixed vector.
    fn readVec16(self: *Reader) Error![]const u8 {
        const n = try self.readU16();
        return self.take(n);
    }
};

// ---------------------------------------------------------------------------
// Bounded writer
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ClientHello
// ---------------------------------------------------------------------------

pub const ClientHelloParams = struct {
    random: [32]u8,
    cookie: []const u8 = &.{},
    /// SRTP protection profiles to advertise in the use_srtp extension.
    srtp_profiles: []const u16,
};

/// Build a ClientHello body offering the ECDHE-ECDSA-AES128-GCM suite plus the
/// supported_groups / ec_point_formats / signature_algorithms / use_srtp
/// extensions a WebRTC peer needs.
pub fn buildClientHello(out: []u8, params: ClientHelloParams) Error![]const u8 {
    var w = Writer{ .buf = out };
    try w.putU16(0xfefd); // client_version DTLS 1.2
    try w.put(&params.random);
    try w.putU8(0); // session_id: empty
    try w.putU8(@intCast(params.cookie.len));
    try w.put(params.cookie);
    // cipher_suites
    try w.putU16(2);
    try w.putU16(cipher_ecdhe_ecdsa_aes128_gcm_sha256);
    // compression_methods: [null]
    try w.putU8(1);
    try w.putU8(0);
    // extensions
    var ext_buf: [256]u8 = undefined;
    var ext = Writer{ .buf = &ext_buf };
    try writeSupportedGroups(&ext);
    try writeEcPointFormats(&ext);
    try writeSignatureAlgorithms(&ext);
    try writeUseSrtp(&ext, params.srtp_profiles);
    try w.putU16(@intCast(ext.pos));
    try w.put(ext.bytes());
    return w.bytes();
}

fn writeExtensionHeader(w: *Writer, ext_type: u16, body_len: usize) Error!void {
    try w.putU16(ext_type);
    try w.putU16(@intCast(body_len));
}

fn writeSupportedGroups(w: *Writer) Error!void {
    try writeExtensionHeader(w, ext_supported_groups, 4);
    try w.putU16(2); // list length
    try w.putU16(named_curve_secp256r1);
}

fn writeEcPointFormats(w: *Writer) Error!void {
    try writeExtensionHeader(w, ext_ec_point_formats, 2);
    try w.putU8(1); // list length
    try w.putU8(ec_point_uncompressed);
}

fn writeSignatureAlgorithms(w: *Writer) Error!void {
    try writeExtensionHeader(w, ext_signature_algorithms, 4);
    try w.putU16(2); // list length
    try w.putU16(sig_scheme_ecdsa_secp256r1_sha256);
}

fn writeUseSrtp(w: *Writer, profiles: []const u16) Error!void {
    var body: [64]u8 = undefined;
    const encoded = dtls_srtp.encodeUseSrtp(profiles, "", &body) catch return error.BadLength;
    try writeExtensionHeader(w, ext_use_srtp, encoded.len);
    try w.put(encoded);
}

pub const ClientHelloView = struct {
    client_version: u16,
    random: [32]u8,
    cookie: []const u8,
    offers_target_cipher: bool,
    /// use_srtp extension body (borrows the input), empty if absent.
    use_srtp_body: []const u8,
};

/// Parse a ClientHello body. Fail-closed on any structural violation.
pub fn parseClientHello(body: []const u8) Error!ClientHelloView {
    var r = Reader{ .buf = body };
    const version = try r.readU16();
    const rand = try r.take(32);
    _ = try r.readVec8(); // session_id
    const cookie = try r.readVec8();
    const suites = try r.readVec16();
    if (suites.len % 2 != 0) return error.BadLength;
    var offers = false;
    var i: usize = 0;
    while (i + 2 <= suites.len) : (i += 2) {
        if (std.mem.readInt(u16, suites[i..][0..2], .big) == cipher_ecdhe_ecdsa_aes128_gcm_sha256) offers = true;
    }
    _ = try r.readVec8(); // compression_methods

    var use_srtp_body: []const u8 = &.{};
    if (r.remaining() > 0) {
        const exts = try r.readVec16();
        use_srtp_body = try findExtension(exts, ext_use_srtp) orelse &.{};
    }

    var out: ClientHelloView = .{
        .client_version = version,
        .random = undefined,
        .cookie = cookie,
        .offers_target_cipher = offers,
        .use_srtp_body = use_srtp_body,
    };
    @memcpy(&out.random, rand[0..32]);
    return out;
}

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

// ---------------------------------------------------------------------------
// ServerHello
// ---------------------------------------------------------------------------

/// Build a ServerHello body selecting the target cipher and echoing exactly one
/// SRTP profile in the use_srtp extension.
pub fn buildServerHello(out: []u8, server_random: [32]u8, cipher_suite: u16, srtp_profile: u16) Error![]const u8 {
    var w = Writer{ .buf = out };
    try w.putU16(0xfefd); // server_version DTLS 1.2
    try w.put(&server_random);
    try w.putU8(0); // session_id: empty
    try w.putU16(cipher_suite);
    try w.putU8(0); // compression: null
    // extensions: use_srtp only
    var ext_buf: [64]u8 = undefined;
    var ext = Writer{ .buf = &ext_buf };
    try writeUseSrtp(&ext, &.{srtp_profile});
    try w.putU16(@intCast(ext.pos));
    try w.put(ext.bytes());
    return w.bytes();
}

pub const ServerHelloView = struct {
    server_version: u16,
    random: [32]u8,
    cipher_suite: u16,
    /// Selected SRTP profile from the use_srtp extension, or null if absent.
    srtp_profile: ?u16,
};

pub fn parseServerHello(body: []const u8) Error!ServerHelloView {
    var r = Reader{ .buf = body };
    const version = try r.readU16();
    const rand = try r.take(32);
    _ = try r.readVec8(); // session_id
    const suite = try r.readU16();
    _ = try r.readU8(); // compression

    var profile: ?u16 = null;
    if (r.remaining() > 0) {
        const exts = try r.readVec16();
        if (try findExtension(exts, ext_use_srtp)) |us| {
            var pr = Reader{ .buf = us };
            const profiles_bytes = try pr.readU16();
            if (profiles_bytes >= 2) profile = try pr.readU16();
        }
    }

    var out: ServerHelloView = .{
        .server_version = version,
        .random = undefined,
        .cipher_suite = suite,
        .srtp_profile = profile,
    };
    @memcpy(&out.random, rand[0..32]);
    return out;
}

// ---------------------------------------------------------------------------
// Certificate
// ---------------------------------------------------------------------------

/// Build a Certificate body carrying the single self-signed leaf `cert_der`.
pub fn buildCertificate(out: []u8, cert_der: []const u8) Error![]const u8 {
    var w = Writer{ .buf = out };
    try w.putU24(@intCast(cert_der.len + 3)); // certificate_list length
    try w.putU24(@intCast(cert_der.len)); // this cert length
    try w.put(cert_der);
    return w.bytes();
}

/// Parse a Certificate body, returning the first (leaf) certificate DER.
pub fn parseCertificate(body: []const u8) Error![]const u8 {
    var r = Reader{ .buf = body };
    const list_len = try r.readU24();
    if (list_len > r.remaining()) return error.BadLength;
    const first_len = try r.readU24();
    if (@as(usize, first_len) + 3 > list_len) return error.BadLength; // cert + its 3-byte len must fit the list
    return r.take(first_len);
}

// ---------------------------------------------------------------------------
// ServerKeyExchange (ECDHE, signed)
// ---------------------------------------------------------------------------

/// Build the ECDHE ServerKeyExchange params (curve_type || named_curve ||
/// point) as signed and as wire-serialised. Returns the params slice.
fn writeEcdheParams(w: *Writer, point: [p256_point_len]u8) Error!void {
    try w.putU8(ec_curve_type_named);
    try w.putU16(named_curve_secp256r1);
    try w.putU8(@intCast(point.len));
    try w.put(&point);
}

/// Serialise the bytes an ECDHE ServerKeyExchange signature covers:
/// `client_random || server_random || ECParameters` (RFC 8422 §5.4).
pub fn serverKeyExchangeSignedData(
    out: []u8,
    client_random: [32]u8,
    server_random: [32]u8,
    point: [p256_point_len]u8,
) Error![]const u8 {
    var w = Writer{ .buf = out };
    try w.put(&client_random);
    try w.put(&server_random);
    try writeEcdheParams(&w, point);
    return w.bytes();
}

/// Build a ServerKeyExchange body: ECParameters + signature algorithm + DER
/// ECDSA signature (`sig_der` produced by the caller over
/// `serverKeyExchangeSignedData`).
pub fn buildServerKeyExchange(out: []u8, point: [p256_point_len]u8, sig_der: []const u8) Error![]const u8 {
    var w = Writer{ .buf = out };
    try writeEcdheParams(&w, point);
    try w.putU16(sig_scheme_ecdsa_secp256r1_sha256);
    try w.putU16(@intCast(sig_der.len));
    try w.put(sig_der);
    return w.bytes();
}

pub const ServerKeyExchangeView = struct {
    point: [p256_point_len]u8,
    sig_scheme: u16,
    sig_der: []const u8,
};

pub fn parseServerKeyExchange(body: []const u8) Error!ServerKeyExchangeView {
    var r = Reader{ .buf = body };
    const curve_type = try r.readU8();
    if (curve_type != ec_curve_type_named) return error.BadLength;
    const named = try r.readU16();
    if (named != named_curve_secp256r1) return error.BadLength;
    const point = try r.readVec8();
    if (point.len != p256_point_len) return error.BadPoint;
    const scheme = try r.readU16();
    const sig = try r.readVec16();

    var out: ServerKeyExchangeView = .{
        .point = undefined,
        .sig_scheme = scheme,
        .sig_der = sig,
    };
    @memcpy(&out.point, point[0..p256_point_len]);
    return out;
}

// ---------------------------------------------------------------------------
// ClientKeyExchange (ECDHE)
// ---------------------------------------------------------------------------

pub fn buildClientKeyExchange(out: []u8, point: [p256_point_len]u8) Error![]const u8 {
    var w = Writer{ .buf = out };
    try w.putU8(@intCast(point.len));
    try w.put(&point);
    return w.bytes();
}

pub fn parseClientKeyExchange(body: []const u8) Error![p256_point_len]u8 {
    var r = Reader{ .buf = body };
    const point = try r.readVec8();
    if (point.len != p256_point_len) return error.BadPoint;
    var out: [p256_point_len]u8 = undefined;
    @memcpy(&out, point[0..p256_point_len]);
    return out;
}

// ---------------------------------------------------------------------------
// Key block (RFC 5246 §6.3) — AES-128-GCM has no MAC keys.
// ---------------------------------------------------------------------------

pub const KeyBlock = struct {
    client_write_key: [16]u8,
    server_write_key: [16]u8,
    client_write_iv: [4]u8,
    server_write_iv: [4]u8,
};

/// Derive the AES-128-GCM key block:
/// PRF(master_secret, "key expansion", server_random || client_random).
pub fn deriveKeyBlock(master_secret: []const u8, client_random: [32]u8, server_random: [32]u8) KeyBlock {
    var seed: [64]u8 = undefined;
    @memcpy(seed[0..32], &server_random); // note: server first for key expansion
    @memcpy(seed[32..64], &client_random);

    var km: [2 * (16 + 4)]u8 = undefined;
    dtls_srtp.prfSha256(master_secret, "key expansion", &seed, &km);

    var kb: KeyBlock = undefined;
    @memcpy(&kb.client_write_key, km[0..16]);
    @memcpy(&kb.server_write_key, km[16..32]);
    @memcpy(&kb.client_write_iv, km[32..36]);
    @memcpy(&kb.server_write_iv, km[36..40]);
    return kb;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "ClientHello round-trips and advertises the target cipher + srtp profile" {
    var rnd: [32]u8 = undefined;
    for (&rnd, 0..) |*b, i| b.* = @intCast(i);
    var buf: [512]u8 = undefined;
    const body = try buildClientHello(&buf, .{
        .random = rnd,
        .cookie = "cook",
        .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
    });

    const view = try parseClientHello(body);
    try testing.expectEqual(@as(u16, 0xfefd), view.client_version);
    try testing.expectEqualSlices(u8, &rnd, &view.random);
    try testing.expectEqualStrings("cook", view.cookie);
    try testing.expect(view.offers_target_cipher);
    try testing.expect(dtls_srtp.offersProfile(view.use_srtp_body, dtls_srtp.profile_aes128_cm_sha1_80));
}

test "ClientHello with empty cookie parses" {
    const rnd: [32]u8 = @splat(7);
    var buf: [512]u8 = undefined;
    const body = try buildClientHello(&buf, .{ .random = rnd, .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80} });
    const view = try parseClientHello(body);
    try testing.expectEqual(@as(usize, 0), view.cookie.len);
}

test "ServerHello round-trips the chosen cipher and profile" {
    const rnd: [32]u8 = @splat(0xAB);
    var buf: [128]u8 = undefined;
    const body = try buildServerHello(&buf, rnd, cipher_ecdhe_ecdsa_aes128_gcm_sha256, dtls_srtp.profile_aes128_cm_sha1_80);
    const view = try parseServerHello(body);
    try testing.expectEqualSlices(u8, &rnd, &view.random);
    try testing.expectEqual(cipher_ecdhe_ecdsa_aes128_gcm_sha256, view.cipher_suite);
    try testing.expectEqual(@as(?u16, dtls_srtp.profile_aes128_cm_sha1_80), view.srtp_profile);
}

test "Certificate round-trips the leaf DER" {
    const cert = "\x30\x82\x01\x00 fake-der-bytes";
    var buf: [64]u8 = undefined;
    const body = try buildCertificate(&buf, cert);
    const leaf = try parseCertificate(body);
    try testing.expectEqualSlices(u8, cert, leaf);
}

test "ServerKeyExchange round-trips point and signature" {
    var point: [p256_point_len]u8 = undefined;
    for (&point, 0..) |*b, i| b.* = @intCast(i +% 4);
    point[0] = 0x04;
    const sig = "\x30\x44 der-ecdsa-sig";
    var buf: [256]u8 = undefined;
    const body = try buildServerKeyExchange(&buf, point, sig);
    const view = try parseServerKeyExchange(body);
    try testing.expectEqualSlices(u8, &point, &view.point);
    try testing.expectEqual(sig_scheme_ecdsa_secp256r1_sha256, view.sig_scheme);
    try testing.expectEqualSlices(u8, sig, view.sig_der);
}

test "ClientKeyExchange round-trips the point" {
    var point: [p256_point_len]u8 = @splat(0x09);
    point[0] = 0x04;
    var buf: [80]u8 = undefined;
    const body = try buildClientKeyExchange(&buf, point);
    const got = try parseClientKeyExchange(body);
    try testing.expectEqualSlices(u8, &point, &got);
}

test "parsers reject truncated input" {
    try testing.expectError(error.Truncated, parseClientHello(&.{ 0xfe, 0xfd }));
    try testing.expectError(error.Truncated, parseServerHello(&.{0x00}));
    try testing.expectError(error.Truncated, parseCertificate(&.{ 0x00, 0x00 }));
    try testing.expectError(error.Truncated, parseServerKeyExchange(&.{ 0x03, 0x00 }));
    try testing.expectError(error.BadPoint, parseClientKeyExchange(&.{ 0x02, 0x01, 0x02 }));
}

test "deriveKeyBlock is deterministic and input-sensitive" {
    const ms: [48]u8 = @splat(0x5a);
    var cr: [32]u8 = @splat(0x10);
    const sr: [32]u8 = @splat(0x20);
    const a = deriveKeyBlock(&ms, cr, sr);
    const b = deriveKeyBlock(&ms, cr, sr);
    try testing.expectEqualSlices(u8, &a.client_write_key, &b.client_write_key);
    try testing.expectEqualSlices(u8, &a.server_write_iv, &b.server_write_iv);
    // Client and server keys differ.
    try testing.expect(!std.mem.eql(u8, &a.client_write_key, &a.server_write_key));
    cr[0] ^= 0xff;
    const c = deriveKeyBlock(&ms, cr, sr);
    try testing.expect(!std.mem.eql(u8, &a.client_write_key, &c.client_write_key));
}
