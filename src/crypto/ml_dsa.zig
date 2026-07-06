// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! ML-DSA-65 (FIPS 204) signature VERIFICATION — from scratch, verify-only.
//!
//! Orochi verifies post-quantum certificate signatures; it never *signs* them,
//! so this module implements only `ML-DSA.Verify` / `ML-DSA.Verify_internal`
//! (FIPS 204 Algorithms 3 and 8) for the ML-DSA-65 parameter set. There is no
//! key generation and no signing here by design.
//!
//! Scope and parameter set (ML-DSA-65, a.k.a. Dilithium3):
//!   q = 8380417, n = 256, (k,l) = (6,5), η = 4, τ = 49, β = τ·η = 196,
//!   γ1 = 2^19, γ2 = (q−1)/32, ω = 55, d = 13, λ = 192 (⇒ c̃ is 48 bytes).
//!   Public key = 1952 bytes (ρ ‖ t1), signature = 3309 bytes (c̃ ‖ z ‖ h).
//!
//! Arithmetic strategy: this is a *verifier* run on public data (certificate
//! chains), not a hot path, and not secret-dependent, so correctness-by-
//! construction beats cleverness. All modular reduction uses a plain `% q`
//! (no Montgomery/Barrett), which removes an entire class of subtle reduction
//! bugs. There is no secret input, so there is no constant-time requirement.
//!
//! Correctness is pinned by INDEPENDENT NIST ACVP FIPS 204 sigVer vectors in
//! `ml_dsa_kat.zig`; a plausible-but-wrong lattice verifier would fail those
//! accept vectors, which is exactly why the KAT — not this code's own output —
//! is the gate.
//!
//! References: FIPS 204 (final, 2024). Algorithm numbers cited inline.

const std = @import("std");
const Shake128 = std.crypto.hash.sha3.Shake128;
const Shake256 = std.crypto.hash.sha3.Shake256;

// ── ML-DSA-65 parameters ────────────────────────────────────────────────────

/// Modulus q = 2^23 − 2^13 + 1.
pub const Q: u32 = 8380417;
/// Ring degree.
pub const N: usize = 256;
/// Matrix rows.
pub const K: usize = 6;
/// Matrix columns / z length.
pub const L: usize = 5;
/// Dropped low bits of t.
pub const D: u32 = 13;
/// Number of ±1 coefficients in the challenge polynomial c.
pub const TAU: usize = 49;
/// Rejection bound β = τ·η.
pub const BETA: i32 = 196;
/// γ1 = 2^19.
pub const GAMMA1: i32 = 1 << 19;
/// γ2 = (q−1)/32.
pub const GAMMA2: i32 = (@as(i32, @intCast(Q)) - 1) / 32;
/// Max hint weight ω.
pub const OMEGA: usize = 55;
/// c̃ length in bytes (2·λ/8 = λ/4 with λ = 192).
pub const CTILDE_LEN: usize = 48;

/// Encoded public-key length (ρ ‖ t1).
pub const public_key_len: usize = 1952;
/// Encoded signature length (c̃ ‖ z ‖ h).
pub const signature_len: usize = 3309;

comptime {
    // Byte-length invariants, derived independently of the constants above so a
    // mistyped parameter is caught at compile time rather than by a KAT.
    std.debug.assert(public_key_len == 32 + K * N * 10 / 8); // ρ + SimpleBitPack(t1,10b)
    std.debug.assert(signature_len == CTILDE_LEN + L * N * 20 / 8 + (OMEGA + K)); // c̃ + z(20b) + h
}

// ── Modular arithmetic in canonical [0, q) ──────────────────────────────────

inline fn addQ(a: u32, b: u32) u32 {
    const s = a + b; // a,b < q < 2^23 ⇒ s < 2^24, no overflow
    return if (s >= Q) s - Q else s;
}

inline fn subQ(a: u32, b: u32) u32 {
    return if (a >= b) a - b else a + Q - b;
}

inline fn mulQ(a: u32, b: u32) u32 {
    return @intCast((@as(u64, a) * @as(u64, b)) % Q);
}

/// Reduce a signed value into canonical [0, q).
inline fn canon(v: i64) u32 {
    const m = @mod(v, @as(i64, Q));
    return @intCast(m);
}

fn modpow(base: u64, exp: u64) u32 {
    var result: u64 = 1;
    var b = base % Q;
    var e = exp;
    while (e > 0) : (e >>= 1) {
        if (e & 1 == 1) result = (result * b) % Q;
        b = (b * b) % Q;
    }
    return @intCast(result);
}

/// n^{-1} mod q, for the inverse-NTT final scaling.
const N_INV: u32 = modpow(N, Q - 2);

comptime {
    std.debug.assert(@as(u64, N_INV) * N % Q == 1);
}

// ── NTT tables ──────────────────────────────────────────────────────────────

/// ζ = 1753 is a primitive 512-th root of unity mod q (FIPS 204).
const ZETA: u64 = 1753;

/// Bit-reverse the low 8 bits of `x`.
fn brv8(x: usize) usize {
    var r: usize = 0;
    var v = x;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        r = (r << 1) | (v & 1);
        v >>= 1;
    }
    return r;
}

/// ZETAS[i] = ζ^{brv8(i)} mod q — the standard Dilithium negacyclic-NTT table.
const ZETAS: [256]u32 = blk: {
    @setEvalBranchQuota(100000);
    var t: [256]u32 = undefined;
    var i: usize = 0;
    while (i < 256) : (i += 1) t[i] = modpow(ZETA, brv8(i));
    break :blk t;
};

comptime {
    // ζ is a primitive 512-th root: ζ^256 ≡ −1 (mod q), ζ^512 ≡ 1.
    std.debug.assert(modpow(ZETA, 256) == Q - 1);
    std.debug.assert(modpow(ZETA, 512) == 1);
}

/// A polynomial with coefficients in canonical [0, q).
const Poly = [N]u32;

/// Forward NTT in place (Cooley-Tukey), matching the Dilithium reference
/// ordering: `t = ζ·a[j+len]; a[j+len] = a[j]−t; a[j] = a[j]+t`.
fn nttForward(a: *Poly) void {
    var k: usize = 0;
    var len: usize = 128;
    while (len >= 1) : (len >>= 1) {
        var start: usize = 0;
        while (start < N) : (start += 2 * len) {
            k += 1;
            const zeta = ZETAS[k];
            var j = start;
            while (j < start + len) : (j += 1) {
                const t = mulQ(zeta, a[j + len]);
                a[j + len] = subQ(a[j], t);
                a[j] = addQ(a[j], t);
            }
        }
    }
}

/// Inverse NTT in place (Gentleman-Sande), then scale by n^{-1}.
fn nttInverse(a: *Poly) void {
    var k: usize = 256;
    var len: usize = 1;
    while (len < N) : (len <<= 1) {
        var start: usize = 0;
        while (start < N) : (start += 2 * len) {
            k -= 1;
            const zeta = Q - ZETAS[k]; // −ζ mod q; ZETAS[k] ∈ [1,q) ⇒ result ∈ [1,q)
            var j = start;
            while (j < start + len) : (j += 1) {
                const t = a[j];
                a[j] = addQ(t, a[j + len]);
                a[j + len] = mulQ(zeta, subQ(t, a[j + len]));
            }
        }
    }
    for (a) |*x| x.* = mulQ(x.*, N_INV);
}

inline fn pointwise(a: Poly, b: Poly) Poly {
    var c: Poly = undefined;
    for (0..N) |i| c[i] = mulQ(a[i], b[i]);
    return c;
}

// ── Bit-level pack/unpack (FIPS 204 §7) ─────────────────────────────────────

/// LSB-first bit reader over a fixed byte slice (matches IntegerToBits, which is
/// little-endian within the stream).
const BitReader = struct {
    bytes: []const u8,
    pos: usize = 0,
    buf: u64 = 0,
    bits: u6 = 0,

    fn read(self: *BitReader, c: u6) u32 {
        while (self.bits < c) {
            self.buf |= @as(u64, self.bytes[self.pos]) << self.bits;
            self.pos += 1;
            self.bits += 8;
        }
        const mask = (@as(u64, 1) << c) - 1;
        const v: u32 = @intCast(self.buf & mask);
        self.buf >>= c;
        self.bits -= c;
        return v;
    }
};

/// LSB-first bit writer into a caller-provided output slice.
const BitWriter = struct {
    out: []u8,
    pos: usize = 0,
    buf: u64 = 0,
    bits: u6 = 0,

    fn write(self: *BitWriter, val: u32, c: u6) void {
        self.buf |= @as(u64, val) << self.bits;
        self.bits += c;
        while (self.bits >= 8) {
            self.out[self.pos] = @truncate(self.buf & 0xff);
            self.pos += 1;
            self.buf >>= 8;
            self.bits -= 8;
        }
    }
};

/// SimpleBitUnpack(v) with `bits`-bit coefficients (Algorithm 18).
fn simpleBitUnpack(v: []const u8, comptime bits: u6) Poly {
    var r = BitReader{ .bytes = v };
    var out: Poly = undefined;
    for (0..N) |i| out[i] = r.read(bits);
    return out;
}

// ── Public-key decode (Algorithm 22 pkDecode) ───────────────────────────────

/// Decode t1 (the k high-half polynomials) from the public key. ρ is the first
/// 32 bytes; each t1_i is SimpleBitPack'd with 10-bit coefficients (320 bytes).
fn decodeT1(pk: []const u8) [K]Poly {
    var t1: [K]Poly = undefined;
    const stride = N * 10 / 8; // 320
    for (0..K) |i| {
        const off = 32 + i * stride;
        t1[i] = simpleBitUnpack(pk[off .. off + stride], 10);
    }
    return t1;
}

// ── Signature decode (Algorithm 26 sigDecode) ───────────────────────────────

const DecodedSig = struct {
    ctilde: [CTILDE_LEN]u8,
    /// z as signed coefficients (BitUnpack, a = γ1−1, b = γ1).
    z: [L][N]i32,
    /// Hint bits per polynomial (0/1).
    h: [K][N]u1,
};

const DecodeError = error{InvalidHint};

/// Decode c̃, z, and the hint h. Returns `error.InvalidHint` when HintBitUnpack
/// rejects the hint encoding (the FIPS 204 ⊥ case) — the caller treats this as a
/// verification failure.
fn decodeSig(sig: []const u8) DecodeError!DecodedSig {
    var out: DecodedSig = undefined;
    @memcpy(&out.ctilde, sig[0..CTILDE_LEN]);

    // z: l polynomials, BitUnpack with 20-bit values, w_i = γ1 − value.
    const z_stride = N * 20 / 8; // 640
    var off: usize = CTILDE_LEN;
    for (0..L) |j| {
        var r = BitReader{ .bytes = sig[off .. off + z_stride] };
        for (0..N) |i| {
            const value: i32 = @intCast(r.read(20));
            out.z[j][i] = GAMMA1 - value;
        }
        off += z_stride;
    }

    // h: HintBitUnpack over the trailing (ω + k) bytes (Algorithm 21).
    const y = sig[off .. off + OMEGA + K];
    for (0..K) |i| @memset(&out.h[i], 0);
    var index: usize = 0;
    for (0..K) |i| {
        const end: usize = y[OMEGA + i];
        if (end < index or end > OMEGA) return error.InvalidHint;
        const first = index;
        while (index < end) {
            if (index > first and y[index - 1] >= y[index]) return error.InvalidHint;
            out.h[i][y[index]] = 1;
            index += 1;
        }
    }
    // Remaining hint slots must be zero padding.
    var p = index;
    while (p < OMEGA) : (p += 1) {
        if (y[p] != 0) return error.InvalidHint;
    }
    return out;
}

/// ‖z‖∞ over all l·256 signed coefficients.
fn zInfNorm(z: [L][N]i32) i32 {
    var m: i32 = 0;
    for (z) |poly| {
        for (poly) |c| {
            const a = if (c < 0) -c else c;
            if (a > m) m = a;
        }
    }
    return m;
}

// ── ExpandA (Algorithm 32) + RejNTTPoly (Algorithm 30) ──────────────────────

/// CoeffFromThreeBytes (Algorithm 14): clear the top bit of b2, assemble a
/// 23-bit little-endian integer, reject if ≥ q.
inline fn coeffFromThreeBytes(b0: u8, b1: u8, b2: u8) ?u32 {
    const z: u32 = @as(u32, b0) | (@as(u32, b1) << 8) | (@as(u32, b2 & 0x7f) << 16);
    return if (z < Q) z else null;
}

/// RejNTTPoly: sample one NTT-domain polynomial by rejection from SHAKE128(seed).
fn rejNttPoly(seed: []const u8) Poly {
    var xof = Shake128.init(.{});
    xof.update(seed);
    var out: Poly = undefined;
    var j: usize = 0;
    var block: [168]u8 = undefined; // SHAKE128 rate
    while (j < N) {
        xof.squeeze(&block);
        var i: usize = 0;
        while (i + 3 <= block.len and j < N) : (i += 3) {
            if (coeffFromThreeBytes(block[i], block[i + 1], block[i + 2])) |c| {
                out[j] = c;
                j += 1;
            }
        }
    }
    return out;
}

/// Â[r][s] = RejNTTPoly(ρ ‖ IntegerToBytes(s,1) ‖ IntegerToBytes(r,1)). Emits the
/// L polynomials of a single row `r`.
fn expandARow(rho: []const u8, r: usize, row: *[L]Poly) void {
    var seed: [34]u8 = undefined;
    @memcpy(seed[0..32], rho[0..32]);
    seed[33] = @intCast(r);
    for (0..L) |s| {
        seed[32] = @intCast(s);
        row[s] = rejNttPoly(&seed);
    }
}

// ── SampleInBall (Algorithm 29) ─────────────────────────────────────────────

/// Sample the challenge polynomial c (τ nonzero ±1 coefficients) from c̃.
fn sampleInBall(ctilde: []const u8) Poly {
    var xof = Shake256.init(.{});
    xof.update(ctilde);
    var signs: [8]u8 = undefined;
    xof.squeeze(&signs);

    var c: Poly = @splat(0);
    var i: usize = N - TAU;
    while (i < N) : (i += 1) {
        var jb: [1]u8 = undefined;
        xof.squeeze(&jb);
        while (jb[0] > i) xof.squeeze(&jb);
        const j = jb[0];
        c[i] = c[j];
        const bit_index = i + TAU - N;
        const bit: u1 = @intCast((signs[bit_index >> 3] >> @intCast(bit_index & 7)) & 1);
        c[j] = if (bit == 0) 1 else Q - 1; // +1 or −1
    }
    return c;
}

// ── Decompose / UseHint / w1Encode (Algorithms 36, 40, 28) ──────────────────

const Decomposed = struct { r1: i32, r0: i32 };

/// Decompose r (canonical [0,q)) into (r1, r0) with r0 = r mod± 2γ2 and the
/// FIPS 204 top-bucket special case.
fn decompose(r: u32) Decomposed {
    const two_g2: i32 = 2 * GAMMA2;
    var r0: i32 = @intCast(@rem(@as(i64, r), @as(i64, two_g2))); // [0, 2γ2)
    if (r0 > GAMMA2) r0 -= two_g2; // (−γ2, γ2]
    const rp: i32 = @intCast(r);
    if (rp - r0 == @as(i32, @intCast(Q)) - 1) {
        return .{ .r1 = 0, .r0 = r0 - 1 };
    }
    const r1: i32 = @intCast(@divExact(@as(i64, rp) - r0, two_g2));
    return .{ .r1 = r1, .r0 = r0 };
}

/// UseHint(hbit, r) → recovered high bits (Algorithm 40). m = (q−1)/(2γ2) = 16.
inline fn useHint(hbit: u1, r: u32) u32 {
    const d = decompose(r);
    if (hbit == 0) return @intCast(d.r1);
    const adjusted: i32 = if (d.r0 > 0) d.r1 + 1 else d.r1 - 1;
    return @intCast(@mod(adjusted, @as(i32, 16)));
}

/// w1Encode: SimpleBitPack each of the k w1 polynomials with 4-bit coefficients
/// (b = 15), concatenated → 768 bytes (Algorithm 28).
fn w1Encode(w1: [K]Poly, out: *[K * N * 4 / 8]u8) void {
    var w = BitWriter{ .out = out };
    for (w1) |poly| {
        for (poly) |c| w.write(c, 4);
    }
}

// ── Verify ──────────────────────────────────────────────────────────────────

/// Verify a ML-DSA-65 signature over the internal message `m_prime` (already
/// domain-separated). Implements `ML-DSA.Verify_internal` (FIPS 204 Algorithm 8).
/// Returns `true` on a valid signature, `false` on any structural or
/// cryptographic failure. Never errors, never panics on attacker-controlled input.
pub fn verifyInternal(pk: []const u8, m_prime: []const u8, sig: []const u8) bool {
    return verifyInternalParts(pk, &.{m_prime}, sig);
}

/// Like `verifyInternal`, but the internal message is provided as an ordered set
/// of byte slices concatenated in place (avoids materializing a large M′).
fn verifyInternalParts(pk: []const u8, m_parts: []const []const u8, sig: []const u8) bool {
    if (pk.len != public_key_len) return false;
    if (sig.len != signature_len) return false;

    const rho = pk[0..32];
    const t1 = decodeT1(pk);
    const dec = decodeSig(sig) catch return false; // ⊥ hint ⇒ reject

    // ‖z‖∞ < γ1 − β.
    if (zInfNorm(dec.z) >= GAMMA1 - BETA) return false;

    // tr = H(pk, 64); μ = H(tr ‖ M′, 64).
    var tr: [64]u8 = undefined;
    {
        var h = Shake256.init(.{});
        h.update(pk);
        h.squeeze(&tr);
    }
    var mu: [64]u8 = undefined;
    {
        var h = Shake256.init(.{});
        h.update(&tr);
        for (m_parts) |part| h.update(part);
        h.squeeze(&mu);
    }

    // c ← SampleInBall(c̃); ĉ ← NTT(c).
    var c = sampleInBall(&dec.ctilde);
    nttForward(&c);

    // NTT(z_j) for each column.
    var z_ntt: [L]Poly = undefined;
    for (0..L) |j| {
        for (0..N) |i| z_ntt[j][i] = canon(dec.z[j][i]);
        nttForward(&z_ntt[j]);
    }

    // NTT(t1_i · 2^d) for each row.
    var t1d_ntt: [K]Poly = undefined;
    for (0..K) |i| {
        for (0..N) |n| t1d_ntt[i][n] = mulQ(t1[i][n], @as(u32, 1) << @intCast(D));
        nttForward(&t1d_ntt[i]);
    }

    // w′Approx = NTT⁻¹(Â∘NTT(z) − ĉ∘NTT(t1·2^d)); then w1 = UseHint(h, w′Approx).
    var w1: [K]Poly = undefined;
    var arow: [L]Poly = undefined;
    for (0..K) |i| {
        expandARow(rho, i, &arow);
        var acc: Poly = @splat(0);
        for (0..L) |j| {
            const prod = pointwise(arow[j], z_ntt[j]);
            for (0..N) |n| acc[n] = addQ(acc[n], prod[n]);
        }
        const ct1 = pointwise(c, t1d_ntt[i]);
        for (0..N) |n| acc[n] = subQ(acc[n], ct1[n]);
        nttInverse(&acc);
        for (0..N) |n| w1[i][n] = useHint(dec.h[i][n], acc[n]);
    }

    // c̃′ = H(μ ‖ w1Encode(w1), λ/4).
    var w1_enc: [K * N * 4 / 8]u8 = undefined;
    w1Encode(w1, &w1_enc);
    var ctilde_prime: [CTILDE_LEN]u8 = undefined;
    {
        var h = Shake256.init(.{});
        h.update(&mu);
        h.update(&w1_enc);
        h.squeeze(&ctilde_prime);
    }

    return ctEqual(&dec.ctilde, &ctilde_prime);
}

/// `ML-DSA.Verify(pk, M, sig, ctx)` for the ML-DSA-65 parameter set (FIPS 204
/// Algorithm 3), pure (non-prehashed) variant. `ctx` is the context string
/// (empty for X.509 certificate signatures per draft-ietf-lamps-dilithium-
/// certificates). Returns `false` on any failure, including `ctx.len > 255`.
pub fn verify65(pk: []const u8, msg: []const u8, ctx: []const u8, sig: []const u8) bool {
    if (ctx.len > 255) return false;
    // M′ = IntegerToBytes(0,1) ‖ IntegerToBytes(|ctx|,1) ‖ ctx ‖ M.
    const prefix = [2]u8{ 0x00, @intCast(ctx.len) };
    return verifyInternalParts(pk, &.{ &prefix, ctx, msg }, sig);
}

/// Length-checked, timing-independent byte compare. (All inputs here are public,
/// so this is hygiene, not a secret-dependency requirement.)
fn ctEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

test "ml-dsa-65 parameter and table self-consistency" {
    // Cheap invariants that would surface a mistyped constant before the
    // (expensive) KAT runs. Independent published-vector KATs live in
    // ml_dsa_kat.zig.
    try std.testing.expectEqual(@as(i32, 261888), GAMMA2);
    try std.testing.expectEqual(@as(i32, 524288), GAMMA1);
    try std.testing.expectEqual(@as(u32, 8380416), @as(u32, @intCast(GAMMA2)) * 32);
    // NTT round-trip on a spread of coefficients is the identity.
    var p: Poly = undefined;
    for (0..N) |i| p[i] = @intCast((i * 7919 + 13) % Q);
    const orig = p;
    nttForward(&p);
    nttInverse(&p);
    try std.testing.expectEqualSlices(u32, &orig, &p);
}
