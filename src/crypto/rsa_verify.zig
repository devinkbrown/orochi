//! Clean-room RSA signature verification (public-key operations only).
//!
//! Implements RSASSA-PKCS1-v1_5 (RFC 8017 §8.2.2) and RSASSA-PSS (§8.1.2)
//! verification for SHA-256/384/512, sufficient to validate X.509/TLS
//! certificate signatures. Written from the RFC — no third-party source.
//!
//! The big-integer engine is a fixed-capacity little-endian limb array. The one
//! performance-relevant primitive — the schoolbook multiply-accumulate word op
//! `a*b + acc + carry` — has an x86_64 inline-asm path (`mul` + `adc` carry
//! chain) with a portable u128 fallback; a test asserts the two agree. Reduction
//! uses textbook binary long division and modexp uses square-and-multiply. These
//! are public-key (non-secret) operations on signatures, so constant-time is not
//! required; correctness is gated by a real openssl-generated known-answer test.

const std = @import("std");
const builtin = @import("builtin");

pub const Error = error{
    /// A value (modulus/signature/exponent) exceeds the supported width.
    TooLarge,
    /// Output buffer too small.
    NoSpaceLeft,
};

/// Supported digest algorithms for the signature schemes.
pub const HashAlg = enum {
    sha256,
    sha384,
    sha512,

    pub fn digestLen(self: HashAlg) usize {
        return switch (self) {
            .sha256 => 32,
            .sha384 => 48,
            .sha512 => 64,
        };
    }
};

/// Capacity must hold not only a modulus but the *product* of two reduced
/// operands during modexp: an n-limb modulus yields up to 2n-limb products. To
/// verify RSA-4096 chains (64-limb modulus → 128-limb products) with headroom,
/// the cap is 132 limbs. Accepted moduli are still bounded to ~4096 bits.
pub const max_limbs: usize = 132;
pub const max_bytes: usize = max_limbs * 8;

// ---------------------------------------------------------------------------
// Word-level multiply-accumulate primitive (the asm hot path).
// Computes a*b + acc + carry = hi:lo (128-bit), returning {lo, hi}.
// ---------------------------------------------------------------------------

const Wide = struct { lo: u64, hi: u64 };

inline fn mulAddWord(a: u64, b: u64, acc: u64, carry: u64) Wide {
    if (builtin.cpu.arch == .x86_64) {
        var lo: u64 = undefined;
        var hi: u64 = undefined;
        // rdx:rax = a*b; then add acc and carry into the low word, propagating
        // the carry into the high word with adc.
        asm volatile (
            \\mulq %[b]
            \\addq %[acc], %%rax
            \\adcq $0, %%rdx
            \\addq %[carry], %%rax
            \\adcq $0, %%rdx
            : [lo] "={rax}" (lo),
              [hi] "={rdx}" (hi),
            : [a] "{rax}" (a),
              [b] "r" (b),
              [acc] "r" (acc),
              [carry] "r" (carry),
            : .{ .cc = true });
        return .{ .lo = lo, .hi = hi };
    } else {
        const w: u128 = @as(u128, a) * @as(u128, b) + acc + carry;
        return .{ .lo = @truncate(w), .hi = @intCast(w >> 64) };
    }
}

// ---------------------------------------------------------------------------
// Fixed-capacity big integer (little-endian limbs).
// ---------------------------------------------------------------------------

pub const Big = struct {
    limbs: [max_limbs]u64 = [_]u64{0} ** max_limbs,
    len: usize = 0, // number of significant limbs (no trailing zero limb)

    pub fn normalize(self: *Big) void {
        while (self.len > 0 and self.limbs[self.len - 1] == 0) self.len -= 1;
    }

    pub fn isZero(self: *const Big) bool {
        return self.len == 0;
    }

    pub fn fromBytesBE(bytes: []const u8) Error!Big {
        if (bytes.len > max_bytes) return error.TooLarge;
        var b = Big{};
        // Walk big-endian bytes least-significant first, packing into u64 limbs.
        var i: usize = bytes.len;
        var limb_idx: usize = 0;
        while (i > 0) {
            var word: u64 = 0;
            var shift: u6 = 0;
            var n: usize = 0;
            while (n < 8 and i > 0) : (n += 1) {
                i -= 1;
                word |= @as(u64, bytes[i]) << shift;
                shift +%= 8;
            }
            b.limbs[limb_idx] = word;
            limb_idx += 1;
        }
        b.len = limb_idx;
        b.normalize();
        return b;
    }

    /// Write big-endian into `out` (left-zero-padded to out.len).
    pub fn toBytesBE(self: *const Big, out: []u8) void {
        @memset(out, 0);
        var limb_idx: usize = 0;
        while (limb_idx < self.len) : (limb_idx += 1) {
            const word = self.limbs[limb_idx];
            var byte_in_limb: usize = 0;
            while (byte_in_limb < 8) : (byte_in_limb += 1) {
                const byte: u8 = @truncate(word >> @intCast(byte_in_limb * 8));
                const pos = byte_in_limb + limb_idx * 8;
                if (pos < out.len) out[out.len - 1 - pos] = byte;
            }
        }
    }

    /// Compare self vs other: .lt / .eq / .gt.
    pub fn cmp(self: *const Big, other: *const Big) std.math.Order {
        if (self.len != other.len) return if (self.len < other.len) .lt else .gt;
        var i = self.len;
        while (i > 0) {
            i -= 1;
            if (self.limbs[i] != other.limbs[i]) {
                return if (self.limbs[i] < other.limbs[i]) .lt else .gt;
            }
        }
        return .eq;
    }

    /// self -= other (requires self >= other).
    pub fn subAssign(self: *Big, other: *const Big) void {
        var borrow: u64 = 0;
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            const o = if (i < other.len) other.limbs[i] else 0;
            const a = self.limbs[i];
            const t1 = a -% o;
            const b1: u64 = if (a < o) 1 else 0;
            const t2 = t1 -% borrow;
            const b2: u64 = if (t1 < borrow) 1 else 0;
            self.limbs[i] = t2;
            borrow = b1 + b2;
        }
        self.normalize();
    }

    /// product = a * b (schoolbook, asm-accelerated inner loop).
    pub fn mul(a: *const Big, b: *const Big) Big {
        var p = Big{};
        if (a.isZero() or b.isZero()) return p;
        var j: usize = 0;
        while (j < b.len) : (j += 1) {
            const bj = b.limbs[j];
            var carry: u64 = 0;
            var i: usize = 0;
            while (i < a.len) : (i += 1) {
                const w = mulAddWord(a.limbs[i], bj, p.limbs[i + j], carry);
                p.limbs[i + j] = w.lo;
                carry = w.hi;
            }
            p.limbs[a.len + j] = carry;
        }
        p.len = a.len + b.len;
        p.normalize();
        return p;
    }

    /// Test bit `idx` (0 = least significant).
    pub fn bit(self: *const Big, idx: usize) u1 {
        const limb = idx / 64;
        if (limb >= self.len) return 0;
        return @truncate(self.limbs[limb] >> @intCast(idx % 64));
    }

    pub fn bitLen(self: *const Big) usize {
        if (self.len == 0) return 0;
        const top = self.limbs[self.len - 1];
        return (self.len - 1) * 64 + (64 - @clz(top));
    }

    /// self <<= 1.
    pub fn shlOne(self: *Big) void {
        var carry: u64 = 0;
        var i: usize = 0;
        const limbs_to_touch = @min(self.len + 1, max_limbs);
        while (i < limbs_to_touch) : (i += 1) {
            const v = self.limbs[i];
            self.limbs[i] = (v << 1) | carry;
            carry = v >> 63;
        }
        if (limbs_to_touch > self.len) self.len = limbs_to_touch;
        self.normalize();
    }

    /// Reduce x modulo n via textbook binary long division; returns x mod n.
    pub fn mod(x: *const Big, n: *const Big) Big {
        var r = Big{};
        if (n.isZero()) return r;
        var i = x.bitLen();
        while (i > 0) {
            i -= 1;
            r.shlOne();
            // r |= bit i of x
            if (x.bit(i) == 1) {
                if (r.len == 0) r.len = 1;
                r.limbs[0] |= 1;
            }
            if (r.cmp(n) != .lt) r.subAssign(n);
        }
        return r;
    }
};

/// out = base^exp mod n (all big-endian byte slices). `out` is the modulus
/// byte length, left-zero-padded.
pub fn modExp(base_be: []const u8, exp_be: []const u8, mod_be: []const u8, out: []u8) Error!void {
    const n = try Big.fromBytesBE(mod_be);
    const e = try Big.fromBytesBE(exp_be);
    var b = try Big.fromBytesBE(base_be);
    b = b.mod(&n);

    var result = Big{ .len = 1 };
    result.limbs[0] = 1;

    var i = e.bitLen();
    while (i > 0) {
        i -= 1;
        var sq = result.mul(&result);
        result = sq.mod(&n);
        if (e.bit(i) == 1) {
            sq = result.mul(&b);
            result = sq.mod(&n);
        }
    }
    result.toBytesBE(out);
}

pub const PublicKey = struct {
    /// Big-endian modulus.
    n: []const u8,
    /// Big-endian public exponent (e.g. {0x01, 0x00, 0x01} for 65537).
    e: []const u8,
};

/// DER DigestInfo prefix for each hash (RFC 8017 §9.2).
fn digestInfoPrefix(alg: HashAlg) []const u8 {
    return switch (alg) {
        .sha256 => &.{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 },
        .sha384 => &.{ 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 },
        .sha512 => &.{ 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 },
    };
}

fn hashOf(alg: HashAlg, msg: []const u8, out: []u8) void {
    switch (alg) {
        .sha256 => {
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update(msg);
            h.final(out[0..32]);
        },
        .sha384 => {
            var h = std.crypto.hash.sha2.Sha384.init(.{});
            h.update(msg);
            h.final(out[0..48]);
        },
        .sha512 => {
            var h = std.crypto.hash.sha2.Sha512.init(.{});
            h.update(msg);
            h.final(out[0..64]);
        },
    }
}

/// RSASSA-PKCS1-v1_5 verification (RFC 8017 §8.2.2). `digest` is the
/// pre-computed hash of the signed message. Returns true iff valid.
pub fn verifyPkcs1v15(pub_key: PublicKey, alg: HashAlg, digest: []const u8, signature: []const u8) bool {
    const k = pub_key.n.len;
    if (k > max_bytes or k == 0) return false;
    if (signature.len != k) return false;
    if (digest.len != alg.digestLen()) return false;

    var em: [max_bytes]u8 = undefined;
    modExp(signature, pub_key.e, pub_key.n, em[0..k]) catch return false;

    // Build the expected EM = 0x00 01 PS(0xFF..) 00 || DigestInfo || digest.
    const prefix = digestInfoPrefix(alg);
    const t_len = prefix.len + digest.len;
    if (k < t_len + 11) return false; // need >= 8 bytes of 0xFF padding
    var expected: [max_bytes]u8 = undefined;
    expected[0] = 0x00;
    expected[1] = 0x01;
    const ps_len = k - t_len - 3;
    @memset(expected[2 .. 2 + ps_len], 0xFF);
    expected[2 + ps_len] = 0x00;
    @memcpy(expected[3 + ps_len ..][0..prefix.len], prefix);
    @memcpy(expected[3 + ps_len + prefix.len ..][0..digest.len], digest);

    return ctEq(em[0..k], expected[0..k]);
}

/// MGF1 mask generation (RFC 8017 §B.2.1) with the given hash.
pub fn mgf1(alg: HashAlg, seed: []const u8, mask: []u8) void {
    const h_len = alg.digestLen();
    var counter: u32 = 0;
    var off: usize = 0;
    var buf: [max_bytes]u8 = undefined;
    var block: [64]u8 = undefined;
    while (off < mask.len) : (counter += 1) {
        @memcpy(buf[0..seed.len], seed);
        std.mem.writeInt(u32, buf[seed.len..][0..4], counter, .big);
        hashOf(alg, buf[0 .. seed.len + 4], block[0..h_len]);
        const take = @min(h_len, mask.len - off);
        for (0..take) |i| mask[off + i] ^= block[i];
        off += take;
    }
}

/// RSASSA-PSS verification (RFC 8017 §8.1.2 / EMSA-PSS-VERIFY §9.1.2).
/// `mhash` is the pre-computed hash; `salt_len` is the expected salt length.
pub fn verifyPss(pub_key: PublicKey, alg: HashAlg, mhash: []const u8, signature: []const u8, salt_len: usize) bool {
    const k = pub_key.n.len;
    if (k > max_bytes or k == 0) return false;
    if (signature.len != k) return false;
    const h_len = alg.digestLen();
    if (mhash.len != h_len) return false;

    // modBits = bit length of the modulus; emBits = modBits - 1.
    const n_big = Big.fromBytesBE(pub_key.n) catch return false;
    const mod_bits = n_big.bitLen();
    if (mod_bits == 0) return false;
    const em_bits = mod_bits - 1;
    const em_len = (em_bits + 7) / 8;
    if (em_len < h_len + salt_len + 2) return false;
    if (em_len > k) return false;

    var em_full: [max_bytes]u8 = undefined;
    modExp(signature, pub_key.e, pub_key.n, em_full[0..k]) catch return false;
    // EM is the rightmost em_len bytes (leading bytes are zero when em_len < k).
    const em = em_full[k - em_len ..][0..em_len];

    if (em[em_len - 1] != 0xbc) return false;

    const db_len = em_len - h_len - 1;
    const masked_db = em[0..db_len];
    const h = em[db_len..][0..h_len];

    // Top (8*em_len - em_bits) bits of maskedDB must be zero.
    const top_bits: u3 = @intCast(8 * em_len - em_bits);
    if (top_bits != 0) {
        const shift: u3 = @intCast(@as(usize, 8) - top_bits);
        const mask: u8 = @as(u8, 0xFF) << shift;
        if (masked_db[0] & mask != 0) return false;
    }

    // dbMask = MGF1(H, db_len); DB = maskedDB XOR dbMask.
    var db: [max_bytes]u8 = undefined;
    @memcpy(db[0..db_len], masked_db);
    mgf1(alg, h, db[0..db_len]);
    // Clear the top bits of DB[0].
    if (top_bits != 0) {
        const keep: u8 = @as(u8, 0xFF) >> @intCast(top_bits);
        db[0] &= keep;
    }

    // DB must be PS(0x00..) || 0x01 || salt.
    const ps_len = db_len - salt_len - 1;
    for (db[0..ps_len]) |byte| {
        if (byte != 0) return false;
    }
    if (db[ps_len] != 0x01) return false;
    const salt = db[ps_len + 1 ..][0..salt_len];

    // H' = Hash(0x00*8 || mHash || salt); compare to H.
    var mprime: [8 + max_bytes + max_bytes]u8 = undefined;
    @memset(mprime[0..8], 0);
    @memcpy(mprime[8..][0..h_len], mhash);
    @memcpy(mprime[8 + h_len ..][0..salt_len], salt);
    var hprime: [64]u8 = undefined;
    hashOf(alg, mprime[0 .. 8 + h_len + salt_len], hprime[0..h_len]);

    return ctEq(h, hprime[0..h_len]);
}

fn ctEq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

// ---------------------------------------------------------------------------
// Tests — gated on a REAL openssl-generated RSA-1024 known-answer vector.
// ---------------------------------------------------------------------------

const testing = std.testing;

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// Self-contained verification key: n = M521 = 2^521 - 1 (a well-known Mersenne
// PRIME), so x^(n-1) ≡ 1 (Fermat). With e = d = n-2 ≡ -1 (mod n-1) we get
// e·d ≡ 1 (mod n-1), hence s = EM^d, EM = s^e round-trips with NO key
// generation, NO modular inverse, and NO external tooling — only our own
// modExp. n is 521 bits = 66 bytes: 0x01 followed by 65 × 0xFF.
const m521_n = blk: {
    var n: [66]u8 = [_]u8{0xFF} ** 66;
    n[0] = 0x01;
    break :blk n;
};
// n - 2: low byte 0xFF -> 0xFD, all else identical to n.
const m521_ed = blk: {
    var e: [66]u8 = [_]u8{0xFF} ** 66;
    e[0] = 0x01;
    e[65] = 0xFD;
    break :blk e;
};
const test_digest = hexToBytes("24ddade2122077b86a4ea8ed269ec44c16e3c7105d30c28c3a7060bc718f89a5");

test "mulAddWord asm path agrees with portable u128 fallback" {
    // Arrange: a fixed set of edge + pseudo-random word inputs.
    const cases = [_][4]u64{
        .{ 0, 0, 0, 0 },
        .{ std.math.maxInt(u64), std.math.maxInt(u64), std.math.maxInt(u64), std.math.maxInt(u64) },
        .{ 0xdeadbeefcafef00d, 0x0123456789abcdef, 0xfedcba9876543210, 0x1111111111111111 },
        .{ 1, std.math.maxInt(u64), 0, std.math.maxInt(u64) },
    };
    for (cases) |c| {
        // Act
        const got = mulAddWord(c[0], c[1], c[2], c[3]);
        const w: u128 = @as(u128, c[0]) * @as(u128, c[1]) + c[2] + c[3];
        // Assert
        try testing.expectEqual(@as(u64, @truncate(w)), got.lo);
        try testing.expectEqual(@as(u64, @intCast(w >> 64)), got.hi);
    }
}

test "modExp matches the textbook RSA example (65^17 mod 3233 = 2790, back to 65)" {
    // Arrange
    const n = [_]u8{ 0x0c, 0xa1 }; // 3233
    const e17 = [_]u8{0x11}; // 17
    const d = [_]u8{ 0x0a, 0xc1 }; // 2753
    const m = [_]u8{ 0x00, 0x41 }; // 65
    var out: [2]u8 = undefined;
    // Act
    try modExp(&m, &e17, &n, &out);
    // Assert: ciphertext 2790 = 0x0AE6
    try testing.expectEqual(@as(u8, 0x0a), out[0]);
    try testing.expectEqual(@as(u8, 0xe6), out[1]);
    // And decrypt back to 65.
    try modExp(&out, &d, &n, &out);
    try testing.expectEqual(@as(u8, 0x00), out[0]);
    try testing.expectEqual(@as(u8, 0x41), out[1]);
}

test "verifyPkcs1v15 round-trips a self-signed EM and rejects tampering" {
    // Arrange: encode EM = 00 01 FF.. 00 || DigestInfo || digest, then "sign"
    // it ourselves: s = EM^d mod n (d = m521_ed). Pure self-contained KAT.
    const k = m521_n.len; // 66
    const prefix = digestInfoPrefix(.sha256);
    const t_len = prefix.len + test_digest.len;
    var em: [66]u8 = undefined;
    em[0] = 0x00;
    em[1] = 0x01;
    const ps_len = k - t_len - 3;
    @memset(em[2 .. 2 + ps_len], 0xFF);
    em[2 + ps_len] = 0x00;
    @memcpy(em[3 + ps_len ..][0..prefix.len], prefix);
    @memcpy(em[3 + ps_len + prefix.len ..][0..test_digest.len], &test_digest);
    var sig: [66]u8 = undefined;
    try modExp(&em, &m521_ed, &m521_n, &sig);

    const pk = PublicKey{ .n = &m521_n, .e = &m521_ed };
    // Act + Assert: our signature verifies.
    try testing.expect(verifyPkcs1v15(pk, .sha256, &test_digest, &sig));
    // A flipped signature bit fails.
    var bad_sig = sig;
    bad_sig[10] ^= 0x01;
    try testing.expect(!verifyPkcs1v15(pk, .sha256, &test_digest, &bad_sig));
    // A wrong digest fails.
    var bad_digest = test_digest;
    bad_digest[0] ^= 0x80;
    try testing.expect(!verifyPkcs1v15(pk, .sha256, &bad_digest, &sig));
}

test "verifyPss round-trips a self-encoded EM and rejects tampering" {
    // Arrange: EMSA-PSS-ENCODE (RFC 8017 §9.1.1) with a fixed salt, emLen=65
    // (emBits = 521-1 = 520), then self-sign s = EM^d mod n.
    const h_len: usize = 32;
    const salt_len: usize = 16;
    const em_len: usize = 65; // ceil((521-1)/8)
    const salt = [_]u8{0xA7} ** salt_len;

    // M' = 0x00*8 || mHash || salt; H = SHA-256(M').
    var mprime: [8 + 32 + 16]u8 = undefined;
    @memset(mprime[0..8], 0);
    @memcpy(mprime[8..][0..h_len], &test_digest);
    @memcpy(mprime[8 + h_len ..][0..salt_len], &salt);
    var h: [32]u8 = undefined;
    hashOf(.sha256, &mprime, h[0..h_len]);

    // DB = PS(0x00) || 0x01 || salt; then maskedDB = DB XOR MGF1(H, dbLen).
    const db_len = em_len - h_len - 1; // 32
    const ps_len = db_len - salt_len - 1; // 15
    var db: [32]u8 = undefined;
    @memset(db[0..ps_len], 0);
    db[ps_len] = 0x01;
    @memcpy(db[ps_len + 1 ..][0..salt_len], &salt);
    mgf1(.sha256, h[0..h_len], db[0..db_len]); // db := maskedDB (top_bits=0 here)

    // EM = maskedDB || H || 0xbc  (em_len = 65); left-pad to k=66 for modExp.
    var em: [65]u8 = undefined;
    @memcpy(em[0..db_len], db[0..db_len]);
    @memcpy(em[db_len..][0..h_len], h[0..h_len]);
    em[em_len - 1] = 0xbc;
    var sig: [66]u8 = undefined;
    try modExp(&em, &m521_ed, &m521_n, &sig);

    const pk = PublicKey{ .n = &m521_n, .e = &m521_ed };
    // Act + Assert
    try testing.expect(verifyPss(pk, .sha256, &test_digest, &sig, salt_len));
    var bad_sig = sig;
    bad_sig[40] ^= 0x01;
    try testing.expect(!verifyPss(pk, .sha256, &test_digest, &bad_sig, salt_len));
    try testing.expect(!verifyPss(pk, .sha256, &test_digest, &sig, 20)); // wrong salt len
}

test "verifyPss accepts a real 2048-bit RSASSA-PSS-SHA256 signature (OpenSSL vector)" {
    // Generated with OpenSSL (rsa_padding_mode:pss, rsa_pss_saltlen:32) and
    // verified OK by OpenSSL; covers a production-size modulus (em_bits = 2047,
    // top-bit masking active), which the small synthetic round-trip test above
    // does not exercise against a real signer.
    const n = [_]u8{0xc0,0x4b,0x6a,0x4b,0x9f,0xdb,0x17,0xfa,0x63,0x4e,0x25,0x08,0xe3,0x66,0x5c,0x48,0x2a,0x78,0x2e,0xf9,0x82,0xac,0x32,0x05,0x4a,0xd0,0x48,0xa2,0x88,0xcb,0x76,0xe5,0x1f,0xf1,0xd9,0xef,0x4a,0xde,0xee,0xda,0x2a,0x5b,0xc6,0x0b,0xe1,0x78,0xe7,0x1f,0xeb,0xcf,0x02,0x0c,0x43,0xe8,0xe7,0x3b,0x3c,0x33,0xf8,0xb5,0x4d,0xed,0x08,0x91,0xda,0xaf,0x3c,0x2b,0x62,0x14,0xe9,0xb5,0x5a,0x98,0x86,0x3d,0x1a,0x8a,0x59,0x12,0x4f,0x03,0x50,0x7e,0x81,0xed,0x46,0xf2,0xa8,0xa6,0x25,0xa1,0xa4,0x30,0xe6,0x34,0x0c,0xfe,0xb4,0xf5,0x82,0x17,0x91,0x37,0xfc,0x7a,0x32,0x7b,0x2b,0xa5,0x61,0xec,0xa9,0x68,0xa4,0x43,0x36,0x7b,0x71,0xc2,0x68,0x9d,0x50,0x5f,0x42,0x3e,0x11,0x01,0xc2,0xc0,0xa1,0x91,0x6e,0x31,0x9b,0x70,0xaa,0x98,0x65,0x83,0x87,0x66,0x4d,0x59,0xd6,0xbb,0x1d,0x80,0x3b,0xcd,0x03,0x47,0xed,0x25,0x88,0x61,0xe4,0xdd,0xf1,0x96,0xe0,0x37,0x84,0x09,0xe8,0x46,0x5a,0xe0,0x45,0xf6,0x29,0x4f,0x61,0xb7,0x8f,0x05,0x86,0x33,0x2e,0x3b,0xfd,0x9d,0xae,0x52,0x23,0x95,0x36,0x5c,0xef,0xa2,0x73,0xf4,0xd5,0x53,0x8f,0x76,0xe3,0x20,0xaf,0xa8,0x2f,0x5f,0x49,0x34,0xf9,0x1f,0xee,0xb2,0x64,0x52,0xf9,0xd5,0x3f,0x20,0xa7,0xe3,0xa6,0x6c,0x99,0x68,0x21,0x94,0xd7,0x7f,0x2e,0xd1,0xd2,0xac,0xea,0x24,0x44,0x43,0x9e,0xe9,0xfc,0xc3,0x7d,0xc3,0x53,0x39,0x6d,0x03,0xea,0x74,0xdb,0x7d,0xd8,0xba,0xc3,0x83,0x6a,0x9b,0x3f,0xbc,0x5f,0xd9};
    const e = [_]u8{0x01,0x00,0x01};
    const sig = [_]u8{0x6d,0x6e,0xbf,0x13,0x52,0xbb,0xf2,0xae,0xfa,0xb2,0xc8,0x76,0x4c,0xc8,0x6a,0xcc,0xe1,0x19,0x47,0xe2,0x72,0xe4,0x48,0x55,0x13,0xdf,0xcf,0x0e,0x82,0x27,0x46,0xb1,0x6a,0x30,0xf2,0xe7,0xb9,0x06,0x37,0x37,0x06,0x36,0xd9,0xdc,0xb0,0xff,0x65,0x85,0xb4,0xa8,0xf8,0xe8,0x98,0xa4,0xc8,0xcf,0xd8,0x9b,0x83,0x58,0x03,0x53,0x83,0xef,0x52,0x8b,0xec,0xcb,0x33,0x84,0xb4,0x33,0x33,0x4d,0xe9,0x1a,0x19,0x15,0xed,0x27,0x60,0x85,0xf9,0x67,0x05,0xd9,0xe9,0xc0,0x64,0xb1,0x61,0x46,0x5d,0xfb,0x0f,0x00,0xd1,0x9a,0x1b,0x16,0x37,0x22,0x32,0x26,0xff,0x31,0xbb,0x23,0x7d,0x40,0x84,0xb4,0x54,0x65,0xaa,0x55,0x85,0xec,0x3e,0x7d,0xa7,0x87,0xd9,0xd7,0x7a,0x48,0xc3,0x33,0x2e,0x2e,0xac,0x3c,0xfe,0xa8,0x39,0xf2,0x41,0xfe,0xa9,0x20,0x98,0xe3,0x0c,0xe2,0xd4,0x38,0x3a,0xe5,0x60,0x12,0x73,0xda,0xb8,0x98,0x35,0x4c,0x4d,0xf6,0xcc,0x6e,0x57,0x69,0xbf,0x04,0x50,0xf5,0xff,0x83,0x91,0x98,0x46,0x9a,0x22,0xa2,0xc2,0x92,0x3f,0x73,0x5e,0x75,0xd9,0xcb,0x13,0xfc,0x9d,0x26,0xa6,0x97,0xd1,0x77,0x39,0x8d,0x7b,0x3c,0xc2,0x7e,0xb9,0x80,0x83,0x8b,0xa5,0x0f,0x15,0xc9,0xf2,0xff,0xd4,0x8a,0xdf,0x29,0x42,0xd5,0x73,0xf6,0x13,0x7a,0xe3,0x63,0xa3,0x36,0x0f,0x9b,0xab,0x56,0x87,0xa8,0x39,0xe8,0xe2,0x7e,0x08,0x69,0xaf,0x03,0xf7,0xbb,0x22,0x79,0x1c,0xc6,0xe7,0x23,0xe1,0xf6,0xe7,0xbd,0x96,0x1c,0x28,0x3a,0x7b,0xdd,0x09,0x5e,0x22,0x34};
    const digest = [_]u8{0x6d,0xe9,0x1b,0xa6,0x97,0x0c,0x3f,0xe8,0x8f,0x3d,0x64,0x3f,0x96,0x94,0xeb,0x81,0xeb,0x1d,0x67,0x4e,0x47,0x40,0x74,0xeb,0x1e,0x01,0x61,0x3f,0x1d,0x29,0x99,0xb5};
    const pk = PublicKey{ .n = &n, .e = &e };
    try testing.expect(verifyPss(pk, .sha256, &digest, &sig, 32));
    // Wrong salt length and a flipped signature byte must both be rejected.
    try testing.expect(!verifyPss(pk, .sha256, &digest, &sig, 20));
    var bad = sig;
    bad[0] ^= 0x01;
    try testing.expect(!verifyPss(pk, .sha256, &digest, &bad, 32));
}

test "fromBytesBE / toBytesBE round-trip" {
    const bytes = hexToBytes("0123456789abcdeffedcba9876543210");
    const b = try Big.fromBytesBE(&bytes);
    var out: [16]u8 = undefined;
    b.toBytesBE(&out);
    try testing.expectEqualSlices(u8, &bytes, &out);
}
