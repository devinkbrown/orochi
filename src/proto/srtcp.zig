//! SRTCP packet protection (RFC 3711 §3.4): AES-128 Counter Mode encryption of
//! the RTCP payload after the first 8 bytes, plus an HMAC-SHA1-80
//! authentication tag over the encrypted packet and appended SRTCP index.
//!
//! This is the transform core only — pure and allocation-free. The caller owns
//! per-SSRC SRTCP index tracking and key agreement.
const std = @import("std");
const aes = std.crypto.core.aes;
const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const srtp = @import("srtp.zig");

pub const auth_tag_len = srtp.auth_tag_len;
pub const index_len: usize = 4;
/// RTCP common header plus sender SSRC, which remain in clear for SRTCP.
pub const rtcp_clear_len: usize = 8;

pub const Error = error{ PacketTooShort, BufferTooSmall, AuthFailed };

fn aesCmXor(key: [srtp.cipher_key_len]u8, iv: [16]u8, buf: []u8) void {
    const ctx = aes.Aes128.initEnc(key);
    var counter = iv;
    var ks: [16]u8 = undefined;
    var i: usize = 0;
    while (i < buf.len) : (i += 16) {
        ctx.encrypt(&ks, &counter);
        const n = @min(@as(usize, 16), buf.len - i);
        for (0..n) |j| buf[i + j] ^= ks[j];
        const c = std.mem.readInt(u16, counter[14..16], .big);
        std.mem.writeInt(u16, counter[14..16], c +% 1, .big);
    }
}

/// Build the AES-CM IV for an SRTCP packet (RFC 3711 §4.1.1 / §3.4):
/// IV = (salt << 16) XOR (SSRC << 64) XOR (srtcp_index << 16).
fn srtcpIv(salt: [srtp.session_salt_len]u8, ssrc: u32, srtcp_index: u31) [16]u8 {
    var iv = [_]u8{0} ** 16;
    @memcpy(iv[0..srtp.session_salt_len], &salt);
    var ssrc_be: [4]u8 = undefined;
    std.mem.writeInt(u32, &ssrc_be, ssrc, .big);
    for (0..4) |i| iv[4 + i] ^= ssrc_be[i];
    var idx_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &idx_be, @as(u64, srtcp_index), .big);
    for (0..6) |i| iv[8 + i] ^= idx_be[2 + i];
    return iv;
}

fn authTag(keys: srtp.SessionKeys, body: []const u8, tag: *[auth_tag_len]u8) void {
    var mac: [HmacSha1.mac_length]u8 = undefined;
    var h = HmacSha1.init(&keys.auth);
    h.update(body);
    h.final(&mac);
    @memcpy(tag, mac[0..auth_tag_len]);
}

/// Protect an RTCP packet into `out`: first 8 bytes clear, encrypted remainder,
/// SRTCP index word with E-bit set, then HMAC-SHA1-80 tag.
pub fn protect(keys: srtp.SessionKeys, srtcp_index: u31, rtcp: []const u8, out: []u8) Error![]const u8 {
    if (rtcp.len < rtcp_clear_len) return error.PacketTooShort;
    const protected_len = rtcp.len + index_len + auth_tag_len;
    if (out.len < protected_len) return error.BufferTooSmall;
    @memcpy(out[0..rtcp.len], rtcp);

    const ssrc = std.mem.readInt(u32, rtcp[4..8], .big);
    aesCmXor(keys.cipher, srtcpIv(keys.salt, ssrc, srtcp_index), out[rtcp_clear_len..rtcp.len]);

    const index_word = @as(u32, 0x80000000) | @as(u32, srtcp_index);
    std.mem.writeInt(u32, out[rtcp.len..][0..index_len], index_word, .big);

    var tag: [auth_tag_len]u8 = undefined;
    authTag(keys, out[0 .. rtcp.len + index_len], &tag);
    @memcpy(out[rtcp.len + index_len ..][0..auth_tag_len], &tag);
    return out[0..protected_len];
}

/// Verify and decrypt an SRTCP packet into `out`. The returned RTCP packet does
/// not include the SRTCP index word or authentication tag.
pub fn unprotect(keys: srtp.SessionKeys, rtcp: []const u8, out: []u8) Error![]const u8 {
    if (rtcp.len < rtcp_clear_len + index_len + auth_tag_len) return error.PacketTooShort;
    const body_len = rtcp.len - auth_tag_len;
    const rtcp_len = body_len - index_len;
    if (out.len < rtcp_len) return error.BufferTooSmall;

    var expected: [auth_tag_len]u8 = undefined;
    authTag(keys, rtcp[0..body_len], &expected);
    if (!std.crypto.timing_safe.eql([auth_tag_len]u8, expected, rtcp[body_len..][0..auth_tag_len].*))
        return error.AuthFailed;

    const index_word = std.mem.readInt(u32, rtcp[rtcp_len..][0..index_len], .big);
    if ((index_word & 0x80000000) == 0) return error.AuthFailed;
    const srtcp_index: u31 = @intCast(index_word & 0x7fffffff);

    @memcpy(out[0..rtcp_len], rtcp[0..rtcp_len]);
    const ssrc = std.mem.readInt(u32, rtcp[4..8], .big);
    aesCmXor(keys.cipher, srtcpIv(keys.salt, ssrc, srtcp_index), out[rtcp_clear_len..rtcp_len]);
    return out[0..rtcp_len];
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

test "protect then unprotect round-trips the RTCP packet" {
    const keys = srtp.deriveSessionKeys(
        hexBytes("E1F97A0D3E018BE0D64FA32C06DE4139"),
        hexBytes("0EC675AD498AFEEBB6960B3AABE6"),
    );
    // RTCP SR: V=2, PT=200, length=5, sender SSRC=0xCAFEBABE, then body.
    const rtcp = hexBytes("80C80005CAFEBABE") ++ "sr-report-body!!".*;
    var protected: [rtcp.len + index_len + auth_tag_len]u8 = undefined;
    const srtcp_packet = try protect(keys, 0x01234567, &rtcp, &protected);
    try testing.expectEqual(@as(usize, rtcp.len + index_len + auth_tag_len), srtcp_packet.len);

    var recovered: [rtcp.len]u8 = undefined;
    const back = try unprotect(keys, srtcp_packet, &recovered);
    try testing.expectEqualSlices(u8, &rtcp, back);
}

test "unprotect rejects a tampered ciphertext byte" {
    const keys = srtp.deriveSessionKeys(
        hexBytes("E1F97A0D3E018BE0D64FA32C06DE4139"),
        hexBytes("0EC675AD498AFEEBB6960B3AABE6"),
    );
    const rtcp = hexBytes("80C80003CAFEBABE") ++ "payload!".*;
    var protected: [rtcp.len + index_len + auth_tag_len]u8 = undefined;
    const srtcp_packet = try protect(keys, 7, &rtcp, &protected);

    var tampered: [rtcp.len + index_len + auth_tag_len]u8 = undefined;
    @memcpy(&tampered, srtcp_packet);
    tampered[rtcp_clear_len] ^= 0x01;
    var recovered: [rtcp.len]u8 = undefined;
    try testing.expectError(error.AuthFailed, unprotect(keys, &tampered, &recovered));
}

test "protect leaves the first 8 RTCP bytes unchanged" {
    const keys = srtp.deriveSessionKeys(
        hexBytes("E1F97A0D3E018BE0D64FA32C06DE4139"),
        hexBytes("0EC675AD498AFEEBB6960B3AABE6"),
    );
    const rtcp = hexBytes("80C80004CAFEBABE") ++ "clear-check!".*;
    var protected: [rtcp.len + index_len + auth_tag_len]u8 = undefined;
    const srtcp_packet = try protect(keys, 0x7fffffff, &rtcp, &protected);
    try testing.expectEqualSlices(u8, rtcp[0..rtcp_clear_len], srtcp_packet[0..rtcp_clear_len]);
}
