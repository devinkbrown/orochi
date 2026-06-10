//! DTLS-SRTP keying (RFC 5764): the `use_srtp` extension profiles and the
//! extraction of SRTP master key/salt material from a (D)TLS master secret via
//! the TLS 1.2 PRF. This is the bridge between a DTLS handshake and the SRTP
//! transform in `srtp.zig`: a handshake negotiates a profile via `use_srtp` and,
//! once the master secret is established, both sides run `exportSrtpKeys` to get
//! the per-direction SRTP master key+salt, then drive `srtp.deriveSessionKeys`.
//!
//! Pure and allocation-free. The DTLS record/handshake state machine that
//! produces the master secret is a separate (larger) layer.
const std = @import("std");
const srtp = @import("srtp.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// SRTP protection profiles (RFC 5764 §4.1.2). Orochi offers the SDES-equivalent
/// AES-128-CM + HMAC-SHA1-80 profile that `srtp.zig` implements.
pub const profile_aes128_cm_sha1_80: u16 = 0x0001;
pub const profile_aes128_cm_sha1_32: u16 = 0x0002;

/// RFC 5764 §4.2 keying-material label for the TLS exporter.
pub const exporter_label = "EXTRACTOR-dtls_srtp";

/// TLS 1.2 PRF (RFC 5246 §5) with SHA-256 = P_SHA256(secret, label || seed).
/// Fills `out` of any length.
pub fn prfSha256(secret: []const u8, label: []const u8, seed: []const u8, out: []u8) void {
    // A(1) = HMAC(secret, label || seed)
    var a: [HmacSha256.mac_length]u8 = undefined;
    {
        var h = HmacSha256.init(secret);
        h.update(label);
        h.update(seed);
        h.final(&a);
    }
    var off: usize = 0;
    while (off < out.len) {
        // out_block = HMAC(secret, A(i) || label || seed)
        var block: [HmacSha256.mac_length]u8 = undefined;
        var h = HmacSha256.init(secret);
        h.update(&a);
        h.update(label);
        h.update(seed);
        h.final(&block);
        const n = @min(block.len, out.len - off);
        @memcpy(out[off .. off + n], block[0..n]);
        off += n;
        // A(i+1) = HMAC(secret, A(i))
        var ha = HmacSha256.init(secret);
        ha.update(&a);
        ha.final(&a);
    }
}

/// Per-direction SRTP master keying material (key+salt), ready for
/// `srtp.deriveSessionKeys`. `client` protects the client→server stream and the
/// server uses it to unprotect; `server` is the reverse.
pub const ExportedKeys = struct {
    client: [srtp.master_key_len + srtp.master_salt_len]u8,
    server: [srtp.master_key_len + srtp.master_salt_len]u8,

    pub fn clientMaster(self: *const ExportedKeys) [srtp.master_key_len]u8 {
        return self.client[0..srtp.master_key_len].*;
    }
    pub fn clientSalt(self: *const ExportedKeys) [srtp.master_salt_len]u8 {
        return self.client[srtp.master_key_len..][0..srtp.master_salt_len].*;
    }
    pub fn serverMaster(self: *const ExportedKeys) [srtp.master_key_len]u8 {
        return self.server[0..srtp.master_key_len].*;
    }
    pub fn serverSalt(self: *const ExportedKeys) [srtp.master_salt_len]u8 {
        return self.server[srtp.master_key_len..][0..srtp.master_salt_len].*;
    }
};

/// Extract SRTP keying material from the DTLS master secret (RFC 5764 §4.2):
/// PRF(master_secret, "EXTRACTOR-dtls_srtp", client_random || server_random),
/// split as client_key(16) || server_key(16) || client_salt(14) || server_salt(14).
pub fn exportSrtpKeys(
    master_secret: []const u8,
    client_random: [32]u8,
    server_random: [32]u8,
) ExportedKeys {
    const klen = srtp.master_key_len;
    const slen = srtp.master_salt_len;
    var seed: [64]u8 = undefined;
    @memcpy(seed[0..32], &client_random);
    @memcpy(seed[32..64], &server_random);

    var km: [2 * (klen + slen)]u8 = undefined;
    prfSha256(master_secret, exporter_label, &seed, &km);

    var out: ExportedKeys = undefined;
    @memcpy(out.client[0..klen], km[0..klen]);
    @memcpy(out.server[0..klen], km[klen .. 2 * klen]);
    @memcpy(out.client[klen..][0..slen], km[2 * klen ..][0..slen]);
    @memcpy(out.server[klen..][0..slen], km[2 * klen + slen ..][0..slen]);
    return out;
}

pub const UseSrtpError = error{ Truncated, BadLength };

/// Encode a `use_srtp` extension body: a list of protection profiles plus an
/// (optional) MKI. Returns the written slice.
pub fn encodeUseSrtp(profiles: []const u16, mki: []const u8, out: []u8) UseSrtpError![]const u8 {
    const profiles_bytes = profiles.len * 2;
    const total = 2 + profiles_bytes + 1 + mki.len;
    if (out.len < total) return error.Truncated;
    std.mem.writeInt(u16, out[0..2], @intCast(profiles_bytes), .big);
    var off: usize = 2;
    for (profiles) |p| {
        std.mem.writeInt(u16, out[off..][0..2], p, .big);
        off += 2;
    }
    out[off] = @intCast(mki.len);
    off += 1;
    @memcpy(out[off..][0..mki.len], mki);
    off += mki.len;
    return out[0..off];
}

pub const UseSrtp = struct {
    /// Number of advertised profiles (scan them with `offersProfile`, which is
    /// endian-safe on the raw body).
    profile_count: usize,
    mki: []const u8, // borrows `body`
};

/// Parse a `use_srtp` extension body. `mki` borrows `body`.
pub fn parseUseSrtp(body: []const u8) UseSrtpError!UseSrtp {
    if (body.len < 3) return error.Truncated;
    const profiles_bytes = std.mem.readInt(u16, body[0..2], .big);
    if (profiles_bytes % 2 != 0) return error.BadLength;
    if (2 + profiles_bytes + 1 > body.len) return error.Truncated;
    const mki_len = body[2 + profiles_bytes];
    if (2 + profiles_bytes + 1 + mki_len > body.len) return error.Truncated;
    return .{
        .profile_count = profiles_bytes / 2,
        .mki = body[2 + profiles_bytes + 1 ..][0..mki_len],
    };
}

/// Whether `body` advertises `wanted` profile, scanning the profile list in a
/// byte-exact, endian-safe way.
pub fn offersProfile(body: []const u8, wanted: u16) bool {
    if (body.len < 2) return false;
    const profiles_bytes = std.mem.readInt(u16, body[0..2], .big);
    if (profiles_bytes % 2 != 0 or 2 + profiles_bytes > body.len) return false;
    var off: usize = 2;
    while (off + 2 <= 2 + profiles_bytes) : (off += 2) {
        if (std.mem.readInt(u16, body[off..][0..2], .big) == wanted) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "TLS 1.2 P_SHA256 matches the well-known PRF test vector" {
    const secret = hexBytes("9bbe436ba940f017b17652849a71db35");
    const seed = hexBytes("a0ba9f936cda311827a6f796ffd5198c");
    var out: [32]u8 = undefined;
    prfSha256(&secret, "test label", &seed, &out);
    try testing.expectEqualSlices(u8, &hexBytes(
        "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a",
    ), &out);
}

test "exportSrtpKeys is deterministic and feeds srtp round-trip" {
    const ms = hexBytes("0102030405060708090a0b0c0d0e0f101112131415161718");
    var cr: [32]u8 = undefined;
    var sr: [32]u8 = undefined;
    for (&cr, 0..) |*b, i| b.* = @intCast(i);
    for (&sr, 0..) |*b, i| b.* = @intCast(255 - i);

    const keys = exportSrtpKeys(&ms, cr, sr);
    // Client and server material differ.
    try testing.expect(!std.mem.eql(u8, &keys.client, &keys.server));

    // Both ends derive SRTP session keys from the *client* master; one protects,
    // the other unprotects — proving the exported material is usable.
    const sk = srtp.deriveSessionKeys(keys.clientMaster(), keys.clientSalt());
    const rtp = hexBytes("8060000100000064CAFEBABE") ++ "frame".*;
    var prot: [rtp.len + srtp.auth_tag_len]u8 = undefined;
    const wire = try srtp.protect(sk, 0, &rtp, &prot);
    var back: [rtp.len]u8 = undefined;
    try testing.expectEqualSlices(u8, &rtp, try srtp.unprotect(sk, 0, wire, &back));
}

test "use_srtp encode/parse round-trips and offersProfile scans" {
    var buf: [64]u8 = undefined;
    const body = try encodeUseSrtp(&.{ profile_aes128_cm_sha1_80, profile_aes128_cm_sha1_32 }, "mki1", &buf);
    try testing.expect(offersProfile(body, profile_aes128_cm_sha1_80));
    try testing.expect(offersProfile(body, profile_aes128_cm_sha1_32));
    try testing.expect(!offersProfile(body, 0x9999));
    const parsed = try parseUseSrtp(body);
    try testing.expectEqual(@as(usize, 2), parsed.profile_count);
    try testing.expectEqualSlices(u8, "mki1", parsed.mki);
}
