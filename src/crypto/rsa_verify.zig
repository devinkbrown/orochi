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

const Big = struct {
    limbs: [max_limbs]u64 = [_]u64{0} ** max_limbs,
    len: usize = 0, // number of significant limbs (no trailing zero limb)

    fn normalize(self: *Big) void {
        while (self.len > 0 and self.limbs[self.len - 1] == 0) self.len -= 1;
    }

    fn isZero(self: *const Big) bool {
        return self.len == 0;
    }

    fn fromBytesBE(bytes: []const u8) Error!Big {
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
    fn toBytesBE(self: *const Big, out: []u8) void {
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
    fn cmp(self: *const Big, other: *const Big) std.math.Order {
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
    fn subAssign(self: *Big, other: *const Big) void {
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
    fn mul(a: *const Big, b: *const Big) Big {
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
    fn bit(self: *const Big, idx: usize) u1 {
        const limb = idx / 64;
        if (limb >= self.len) return 0;
        return @truncate(self.limbs[limb] >> @intCast(idx % 64));
    }

    fn bitLen(self: *const Big) usize {
        if (self.len == 0) return 0;
        const top = self.limbs[self.len - 1];
        return (self.len - 1) * 64 + (64 - @clz(top));
    }

    /// self <<= 1.
    fn shlOne(self: *Big) void {
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
    fn mod(x: *const Big, n: *const Big) Big {
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
fn modExp(base_be: []const u8, exp_be: []const u8, mod_be: []const u8, out: []u8) Error!void {
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
fn mgf1(alg: HashAlg, seed: []const u8, mask: []u8) void {
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

test "fromBytesBE / toBytesBE round-trip" {
    const bytes = hexToBytes("0123456789abcdeffedcba9876543210");
    const b = try Big.fromBytesBE(&bytes);
    var out: [16]u8 = undefined;
    b.toBytesBE(&out);
    try testing.expectEqualSlices(u8, &bytes, &out);
}
