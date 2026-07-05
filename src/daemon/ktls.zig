// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux kTLS (kernel TLS offload) — Phase 0 foundation.
//!
//! Pure encoders + constants for the kernel TLS ULP, with NO syscalls and NO
//! live wiring. This is the byte-layout half of `docs/dev/tls-design/ktls.md`
//! Phase 0: the `SOL_TLS`/`TLS_TX` sockopt constants, the per-cipher
//! `tls12_crypto_info_*` struct geometry (Linux UAPI `include/uapi/linux/tls.h`),
//! a serializer that produces the exact bytes `setsockopt(SOL_TLS, TLS_TX, …)`
//! expects, and the TLS 1.3 static-IV → salt/iv split.
//!
//! Scope discipline:
//!   * **Authoritative + unit-tested here:** the sockopt constants, the cipher
//!     geometry, the `crypto_info` byte layout (field order iv‖key‖salt‖rec_seq
//!     after the 4-byte `tls_crypto_info` header), the big-endian `rec_seq`
//!     encoding, and the TLS 1.3 nonce split (salt = static_iv[0..4],
//!     iv = static_iv[4..12] for AES-GCM; salt-less, iv = the full 12-byte IV for
//!     ChaCha20-Poly1305 — RFC 8446 §5.3, matching how the kernel XORs the record
//!     sequence into the `iv` field).
//!   * **Deferred to Phase 1** (needs a real kernel round-trip to validate):
//!     the TLS 1.2 explicit-nonce derivation, the `TCP_ULP` attach + `setsockopt`
//!     calls, the boot-time per-suite capability probe, and the getsockopt-seq
//!     liveness self-test. Those are intentionally NOT in this module.
//!
//! The daemon is 64-bit little-endian only (x86_64 / aarch64); the `u16`
//! `version`/`cipher_type` fields are encoded in native (little) endianness,
//! exactly as the kernel reads the C struct.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;

const native_endian = builtin.cpu.arch.endian();

// ── Socket option constants (Linux UAPI) ────────────────────────────────────
/// `IPPROTO_TCP` — the level at which `TCP_ULP` is set.
pub const SOL_TCP: u32 = 6;
/// `SOL_TLS` — the level for `TLS_TX` / `TLS_RX` after the ULP is attached.
pub const SOL_TLS: u32 = 282;
/// `TCP_ULP` — attach an Upper Layer Protocol (value "tls"). One-way/permanent.
pub const TCP_ULP: u32 = 31;
/// `TLS_TX` / `TLS_RX` sockopt names under `SOL_TLS`.
pub const TLS_TX: u32 = 1;
pub const TLS_RX: u32 = 2;
/// The ULP name passed to `setsockopt(SOL_TCP, TCP_ULP, …)`.
pub const ulp_name = "tls";

/// TLS protocol versions as the kernel `tls_crypto_info.version` field wants them.
pub const TLS_1_2_VERSION: u16 = 0x0303;
pub const TLS_1_3_VERSION: u16 = 0x0304;

/// Kernel `tls_crypto_info.cipher_type` registry values.
pub const CipherType = enum(u16) {
    aes_gcm_128 = 51,
    aes_gcm_256 = 52,
    chacha20_poly1305 = 54,

    pub fn toInt(self: CipherType) u16 {
        return @intFromEnum(self);
    }
};

/// Fixed 4-byte `tls_crypto_info` header (version + cipher_type) preceding every
/// cipher-specific body.
pub const crypto_info_header_len: usize = 4;
/// Every kTLS cipher uses an 8-byte record sequence number.
pub const rec_seq_len: usize = 8;

/// The AEAD suites orochi can offload, with their kernel geometry. Sizes are the
/// `TLS_CIPHER_*_{IV,KEY,SALT,REC_SEQ}_SIZE` constants from the UAPI header.
pub const Cipher = enum {
    aes_gcm_128,
    aes_gcm_256,
    chacha20_poly1305,

    pub fn cipherType(self: Cipher) CipherType {
        return switch (self) {
            .aes_gcm_128 => .aes_gcm_128,
            .aes_gcm_256 => .aes_gcm_256,
            .chacha20_poly1305 => .chacha20_poly1305,
        };
    }

    /// `iv` field length (the trailing nonce half the kernel XORs the seq into).
    pub fn ivLen(self: Cipher) usize {
        return switch (self) {
            .aes_gcm_128, .aes_gcm_256 => 8,
            .chacha20_poly1305 => 12,
        };
    }

    pub fn keyLen(self: Cipher) usize {
        return switch (self) {
            .aes_gcm_128 => 16,
            .aes_gcm_256, .chacha20_poly1305 => 32,
        };
    }

    /// `salt` field length (the fixed nonce prefix; zero for ChaCha20-Poly1305).
    pub fn saltLen(self: Cipher) usize {
        return switch (self) {
            .aes_gcm_128, .aes_gcm_256 => 4,
            .chacha20_poly1305 => 0,
        };
    }

    /// Total serialized `tls12_crypto_info_*` size for this cipher.
    pub fn cryptoInfoLen(self: Cipher) usize {
        return crypto_info_header_len + self.ivLen() + self.keyLen() + self.saltLen() + rec_seq_len;
    }
};

/// The largest serialized `crypto_info` across all supported ciphers — a caller
/// can stack-allocate this and pass a sub-slice to `encode`.
pub const max_crypto_info_len: usize = crypto_info_header_len + 12 + 32 + 4 + rec_seq_len; // 60

pub const Error = error{
    /// A component slice length did not match the cipher's geometry.
    BadLength,
    /// The output buffer was smaller than `cipher.cryptoInfoLen()`.
    NoSpaceLeft,
};

/// A decomposed kTLS `crypto_info`, ready to serialize for `setsockopt`.
pub const CryptoInfo = struct {
    /// `TLS_1_2_VERSION` or `TLS_1_3_VERSION`.
    version: u16,
    cipher: Cipher,
    /// `saltLen()` bytes (the fixed nonce prefix; empty for ChaCha20-Poly1305).
    salt: []const u8,
    /// `ivLen()` bytes.
    iv: []const u8,
    /// `keyLen()` bytes.
    key: []const u8,
    /// The initial record sequence number, big-endian (see `seqToBytes`).
    rec_seq: [rec_seq_len]u8,

    pub fn encodedLen(self: CryptoInfo) usize {
        return self.cipher.cryptoInfoLen();
    }

    /// Serialize into `out` and return the written prefix. Field order matches the
    /// kernel `tls12_crypto_info_*` struct exactly: `{u16 version, u16 cipher_type}`
    /// (native-endian) then `iv`, `key`, `salt`, `rec_seq` as raw bytes.
    pub fn encode(self: CryptoInfo, out: []u8) Error![]u8 {
        if (self.salt.len != self.cipher.saltLen() or
            self.iv.len != self.cipher.ivLen() or
            self.key.len != self.cipher.keyLen())
        {
            return error.BadLength;
        }
        const total = self.encodedLen();
        if (out.len < total) return error.NoSpaceLeft;

        std.mem.writeInt(u16, out[0..2], self.version, native_endian);
        std.mem.writeInt(u16, out[2..4], self.cipher.cipherType().toInt(), native_endian);
        var p: usize = crypto_info_header_len;
        @memcpy(out[p..][0..self.iv.len], self.iv);
        p += self.iv.len;
        @memcpy(out[p..][0..self.key.len], self.key);
        p += self.key.len;
        @memcpy(out[p..][0..self.salt.len], self.salt);
        p += self.salt.len;
        @memcpy(out[p..][0..rec_seq_len], &self.rec_seq);
        p += rec_seq_len;
        return out[0..p];
    }
};

/// Encode a record sequence number as the kernel's 8-byte big-endian `rec_seq`.
pub fn seqToBytes(seq: u64) [rec_seq_len]u8 {
    var b: [rec_seq_len]u8 = undefined;
    std.mem.writeInt(u64, &b, seq, .big);
    return b;
}

/// Build the TLS 1.3 `CryptoInfo` from a completed handshake's traffic material.
/// `static_iv` is the 12-byte TLS 1.3 write IV (`TrafficKeys.iv`), `key` the
/// traffic key, `seq` the current write sequence number. Per RFC 8446 §5.3 the
/// kernel forms each record nonce as `static_iv XOR (0^4 ‖ seq)`, which the AEAD
/// UAPI expresses as salt = the fixed leading bytes, iv = the trailing bytes the
/// seq is XORed into: AES-GCM splits 12 → salt(4)‖iv(8); ChaCha20-Poly1305 has
/// no salt and the whole 12-byte IV is the `iv` field.
pub fn tls13CryptoInfo(cipher: Cipher, static_iv: []const u8, key: []const u8, seq: u64) Error!CryptoInfo {
    if (static_iv.len != 12) return error.BadLength;
    if (key.len != cipher.keyLen()) return error.BadLength;
    const salt_len = cipher.saltLen();
    return .{
        .version = TLS_1_3_VERSION,
        .cipher = cipher,
        .salt = static_iv[0..salt_len],
        .iv = static_iv[salt_len..],
        .key = key,
        .rec_seq = seqToBytes(seq),
    };
}

// ── Boot-time capability probe (design Phase 0) ─────────────────────────────
// A no-syscall-per-cipher check of whether the running kernel offers the TLS
// ULP at all. The per-suite TLS_TX/RX acceptance probe + the setsockopt attach
// primitives are Phase 1 (they need an ESTABLISHED socket and a deploy-kernel
// round-trip), and are intentionally not here.

/// Path the kernel exposes its available TCP ULPs at.
pub const available_ulp_path = "/proc/sys/net/ipv4/tcp_available_ulp";

/// True when the space/newline-separated ULP list (the contents of
/// `available_ulp_path`) offers the `tls` ULP — i.e. the kernel has CONFIG_TLS
/// and kTLS can be attached. Matches whole tokens, never a substring.
pub fn ulpAvailable(available_ulp_contents: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, available_ulp_contents, " \t\r\n");
    while (it.next()) |tok| {
        if (std.mem.eql(u8, tok, ulp_name)) return true;
    }
    return false;
}

/// Boot-time probe: does the running kernel offer the TLS ULP? Reads
/// `available_ulp_path`. Returns false on non-Linux or any read error (⇒ kTLS
/// unavailable — the daemon simply keeps terminating TLS in userspace). This is
/// the check that answers "is this deploy kernel kTLS-capable?" from the logs.
pub fn probeUlpSupport() bool {
    if (builtin.os.tag != .linux) return false;
    const rc = linux.open(available_ulp_path, .{ .ACCMODE = .RDONLY }, 0);
    if (posix.errno(rc) != .SUCCESS) return false;
    const fd: linux.fd_t = @intCast(rc);
    defer {
        _ = linux.close(fd);
    }
    var buf: [256]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const r = linux.read(fd, buf[total..].ptr, buf.len - total);
        switch (posix.errno(r)) {
            .SUCCESS => {
                const n: usize = @intCast(r);
                if (n == 0) break;
                total += n;
            },
            .INTR => continue,
            else => return false,
        }
    }
    return ulpAvailable(buf[0..total]);
}

// ── Attach primitives (used by the Phase 1 send-seam; validated here) ────────

pub const AttachError = error{
    /// The kernel refused the TLS ULP (no CONFIG_TLS, or non-Linux).
    KtlsUlpUnsupported,
    /// The kernel refused the TX crypto state (unsupported suite/kernel, or the
    /// socket was not ESTABLISHED).
    KtlsTxUnsupported,
};

/// Attach the TLS ULP to `fd` (`setsockopt(SOL_TCP, TCP_ULP, "tls")`). One-way
/// and permanent; the socket must be TCP. `TLS_TX`/`TLS_RX` additionally require
/// it to be ESTABLISHED.
pub fn attachUlp(fd: linux.fd_t) AttachError!void {
    if (builtin.os.tag != .linux) return error.KtlsUlpUnsupported;
    const rc = linux.setsockopt(fd, @intCast(SOL_TCP), TCP_ULP, ulp_name.ptr, @intCast(ulp_name.len));
    if (posix.errno(rc) != .SUCCESS) return error.KtlsUlpUnsupported;
}

/// Install the server→client TX crypto state (`setsockopt(SOL_TLS, TLS_TX)`) from
/// an already-encoded `crypto_info` (see `CryptoInfo.encode`). Requires
/// `attachUlp` first and an ESTABLISHED socket; thereafter the kernel encrypts
/// plaintext written to `fd`.
pub fn attachTx(fd: linux.fd_t, crypto_info: []const u8) AttachError!void {
    if (builtin.os.tag != .linux) return error.KtlsTxUnsupported;
    const rc = linux.setsockopt(fd, @intCast(SOL_TLS), TLS_TX, crypto_info.ptr, @intCast(crypto_info.len));
    if (posix.errno(rc) != .SUCCESS) return error.KtlsTxUnsupported;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "cipher geometry matches the Linux UAPI sizes" {
    try testing.expectEqual(@as(u16, 51), Cipher.aes_gcm_128.cipherType().toInt());
    try testing.expectEqual(@as(u16, 52), Cipher.aes_gcm_256.cipherType().toInt());
    try testing.expectEqual(@as(u16, 54), Cipher.chacha20_poly1305.cipherType().toInt());

    // {iv, key, salt} sizes and the total struct length per cipher.
    try testing.expectEqual(@as(usize, 40), Cipher.aes_gcm_128.cryptoInfoLen()); // 4+8+16+4+8
    try testing.expectEqual(@as(usize, 56), Cipher.aes_gcm_256.cryptoInfoLen()); // 4+8+32+4+8
    try testing.expectEqual(@as(usize, 56), Cipher.chacha20_poly1305.cryptoInfoLen()); // 4+12+32+0+8
    try testing.expect(Cipher.aes_gcm_128.cryptoInfoLen() <= max_crypto_info_len);
    try testing.expect(Cipher.aes_gcm_256.cryptoInfoLen() <= max_crypto_info_len);
    try testing.expect(Cipher.chacha20_poly1305.cryptoInfoLen() <= max_crypto_info_len);
}

test "seqToBytes encodes big-endian" {
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }, &seqToBytes(0));
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 }, &seqToBytes(1));
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }, &seqToBytes(0x0123456789abcdef));
}

test "encode lays out AES-GCM-128 exactly as the kernel struct" {
    const key = [_]u8{0xAA} ** 16;
    const iv = [_]u8{0xBB} ** 8;
    const salt = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const info = CryptoInfo{
        .version = TLS_1_3_VERSION,
        .cipher = .aes_gcm_128,
        .salt = &salt,
        .iv = &iv,
        .key = &key,
        .rec_seq = seqToBytes(7),
    };
    var buf: [max_crypto_info_len]u8 = undefined;
    const out = try info.encode(&buf);

    try testing.expectEqual(@as(usize, 40), out.len);
    // header: version then cipher_type, native-endian.
    try testing.expectEqual(TLS_1_3_VERSION, std.mem.readInt(u16, out[0..2], native_endian));
    try testing.expectEqual(@as(u16, 51), std.mem.readInt(u16, out[2..4], native_endian));
    // body: iv (8) ‖ key (16) ‖ salt (4) ‖ rec_seq (8).
    try testing.expectEqualSlices(u8, &iv, out[4..12]);
    try testing.expectEqualSlices(u8, &key, out[12..28]);
    try testing.expectEqualSlices(u8, &salt, out[28..32]);
    try testing.expectEqualSlices(u8, &seqToBytes(7), out[32..40]);
}

test "encode rejects mismatched component lengths and a short buffer" {
    const info = CryptoInfo{
        .version = TLS_1_3_VERSION,
        .cipher = .aes_gcm_128,
        .salt = &[_]u8{ 1, 2, 3 }, // wrong: needs 4
        .iv = &[_]u8{0} ** 8,
        .key = &[_]u8{0} ** 16,
        .rec_seq = seqToBytes(0),
    };
    var buf: [max_crypto_info_len]u8 = undefined;
    try testing.expectError(error.BadLength, info.encode(&buf));

    const ok = CryptoInfo{
        .version = TLS_1_3_VERSION,
        .cipher = .aes_gcm_128,
        .salt = &[_]u8{ 1, 2, 3, 4 },
        .iv = &[_]u8{0} ** 8,
        .key = &[_]u8{0} ** 16,
        .rec_seq = seqToBytes(0),
    };
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, ok.encode(&tiny));
}

test "tls13CryptoInfo splits the AES-GCM static IV into salt(4)+iv(8)" {
    var static_iv: [12]u8 = undefined;
    for (&static_iv, 0..) |*b, i| b.* = @intCast(i + 1); // 01 02 … 0c
    const key = [_]u8{0xCC} ** 16;

    const info = try tls13CryptoInfo(.aes_gcm_128, &static_iv, &key, 42);
    try testing.expectEqual(TLS_1_3_VERSION, info.version);
    try testing.expectEqualSlices(u8, static_iv[0..4], info.salt); // 01 02 03 04
    try testing.expectEqualSlices(u8, static_iv[4..12], info.iv); // 05 … 0c
    try testing.expectEqualSlices(u8, &key, info.key);
    try testing.expectEqualSlices(u8, &seqToBytes(42), &info.rec_seq);

    // It also encodes to the full struct.
    var buf: [max_crypto_info_len]u8 = undefined;
    const out = try info.encode(&buf);
    try testing.expectEqual(@as(usize, 40), out.len);
}

test "tls13CryptoInfo gives ChaCha20-Poly1305 no salt and the full 12-byte IV" {
    var static_iv: [12]u8 = undefined;
    for (&static_iv, 0..) |*b, i| b.* = @intCast(0xF0 + i);
    const key = [_]u8{0xDD} ** 32;

    const info = try tls13CryptoInfo(.chacha20_poly1305, &static_iv, &key, 3);
    try testing.expectEqual(@as(usize, 0), info.salt.len);
    try testing.expectEqualSlices(u8, &static_iv, info.iv); // all 12 bytes
    try testing.expectEqual(@as(usize, 56), info.encodedLen());
}

test "tls13CryptoInfo rejects a wrong IV or key length" {
    const key = [_]u8{0} ** 16;
    try testing.expectError(error.BadLength, tls13CryptoInfo(.aes_gcm_128, &[_]u8{0} ** 11, &key, 0));
    try testing.expectError(error.BadLength, tls13CryptoInfo(.aes_gcm_128, &[_]u8{0} ** 12, &[_]u8{0} ** 15, 0));
}

test "ulpAvailable matches the tls ULP token exactly" {
    // The real /proc/sys/net/ipv4/tcp_available_ulp shape on a CONFIG_TLS kernel.
    try testing.expect(ulpAvailable("espintcp mptcp tls\n"));
    try testing.expect(ulpAvailable("tls"));
    try testing.expect(ulpAvailable("tls mptcp"));
    // No tls ULP.
    try testing.expect(!ulpAvailable("espintcp mptcp\n"));
    try testing.expect(!ulpAvailable(""));
    // Whole-token match only — no substring false positives.
    try testing.expect(!ulpAvailable("tlsx notls\n"));
}

/// Establish an ESTABLISHED loopback TCP pair, attach the TLS ULP to the server
/// end, and install our encoded TLS 1.3 `crypto_info` for `cipher` via TLS_TX —
/// asserting the running kernel ACCEPTS the struct (a wrong size/version/
/// cipher_type/field-order would EINVAL). Skips (not fails) when sockets or the
/// TLS ULP are unavailable (sandbox / no CONFIG_TLS); a rejected but supported
/// suite surfaces as `error.KtlsTxUnsupported`.
fn tcpSocketOrSkip() !linux.fd_t {
    const rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM, linux.IPPROTO.TCP);
    if (posix.errno(rc) != .SUCCESS) return error.SkipZigTest;
    return @intCast(rc);
}

fn expectKernelAcceptsTx(cipher: Cipher, key_len: usize) !void {
    const listen_fd = try tcpSocketOrSkip();
    defer _ = linux.close(listen_fd);
    var addr = linux.sockaddr.in{
        .port = 0, // kernel-assigned ephemeral port
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001), // 127.0.0.1
    };
    if (posix.errno(linux.bind(listen_fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    if (posix.errno(linux.listen(listen_fd, 1)) != .SUCCESS) return error.SkipZigTest;
    // Read the assigned port back into `addr` for the client connect.
    var storage: posix.sockaddr.storage = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    if (posix.errno(linux.getsockname(listen_fd, @ptrCast(&storage), &slen)) != .SUCCESS) return error.SkipZigTest;
    addr.port = (@as(*const linux.sockaddr.in, @ptrCast(@alignCast(&storage)))).port;

    const client_fd = try tcpSocketOrSkip();
    defer _ = linux.close(client_fd);
    if (posix.errno(linux.connect(client_fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    const accept_rc = linux.accept4(listen_fd, null, null, 0);
    if (posix.errno(accept_rc) != .SUCCESS) return error.SkipZigTest;
    const server_fd: linux.fd_t = @intCast(accept_rc);
    defer _ = linux.close(server_fd);

    attachUlp(server_fd) catch return error.SkipZigTest; // no CONFIG_TLS ⇒ skip

    var static_iv = [_]u8{0xAB} ** 12;
    var key = [_]u8{0xCD} ** 32;
    const info = try tls13CryptoInfo(cipher, &static_iv, key[0..key_len], 0);
    var enc: [max_crypto_info_len]u8 = undefined;
    const encoded = try info.encode(&enc);
    try attachTx(server_fd, encoded); // the kernel validates the struct here
}

test "kernel accepts our encoded crypto_info via TLS_TX (validates layout vs real kernel)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // AES-GCM-128 + TLS 1.3 is available on any kTLS-capable kernel (≥5.1); its
    // acceptance validates the crypto_info header + field order + rec_seq layout.
    // A rejection here is a real layout bug (not a missing cipher), so it fails.
    try expectKernelAcceptsTx(.aes_gcm_128, 16);
    // AES-GCM-256 (≥5.2) and ChaCha20-Poly1305 (≥5.11) may be absent on older
    // kernels — validate their layout where supported, tolerate genuine absence.
    expectKernelAcceptsTx(.aes_gcm_256, 32) catch |e| if (e != error.KtlsTxUnsupported) return e;
    expectKernelAcceptsTx(.chacha20_poly1305, 32) catch |e| if (e != error.KtlsTxUnsupported) return e;
}
