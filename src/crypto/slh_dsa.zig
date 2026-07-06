// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SLH-DSA (SPHINCS+, FIPS 205) signature VERIFICATION — from scratch,
//! verify-only, parameter set SLH-DSA-SHA2-128s.
//!
//! Orochi verifies post-quantum certificate signatures; it never *signs* them,
//! so this module implements only `slh_verify` / `slh_verify_internal`
//! (FIPS 205 Algorithms 24 and 20) for the SLH-DSA-SHA2-128s parameter set.
//! There is no key generation and no signing here by design.
//!
//! Parameter set (SLH-DSA-SHA2-128s, security category 1):
//!   n = 16, h = 63, d = 7, h′ = h/d = 9, a = 12, k = 14, lg_w = 4 (w = 16),
//!   m = 30, len1 = 32, len2 = 3, len = 35.
//!   Public key = 32 bytes (PK.seed ‖ PK.root), signature = 7856 bytes.
//!
//! Hash-function instantiation (FIPS 205 §11.2, the SHA-2 category-1 family —
//! for n = 16 *all* of F, H, T_ℓ use SHA-256; only categories 3/5 pull in
//! SHA-512):
//!   F/H/T_ℓ(PK.seed, ADRS, M) = Trunc_16(SHA-256(PK.seed ‖ toByte(0,48) ‖
//!                                                  ADRS^c ‖ M))
//!   H_msg(R, PK.seed, PK.root, M) = MGF1-SHA-256(R ‖ PK.seed ‖
//!                                     SHA-256(R ‖ PK.seed ‖ PK.root ‖ M), 30)
//! where ADRS^c is the 22-byte SHA-2 *compressed* address
//! (ADRS[3] ‖ ADRS[8:16] ‖ ADRS[19] ‖ ADRS[20:32]). The 64-byte prefix
//! `PK.seed ‖ toByte(0,48)` lands exactly on a SHA-256 block boundary, so it is
//! precomputed once as a streaming midstate and cloned per tweakable-hash call.
//!
//! Strategy: this is a *verifier* run on public data (certificate chains), not a
//! secret-dependent hot path, so it is a direct, allocation-free transcription
//! of the FIPS 205 algorithms — correctness-by-construction over cleverness.
//! There is no secret input and therefore no constant-time requirement.
//!
//! Correctness is pinned by INDEPENDENT NIST ACVP FIPS 205 `SLH-DSA-sigVer`
//! vectors (parameter set SLH-DSA-SHA2-128s) in `slh_dsa_kat.zig`; a
//! plausible-but-wrong hash-based verifier fails those accept vectors, which is
//! exactly why the KAT — not this code's own output — is the gate.
//!
//! References: FIPS 205 (final, 2024). Algorithm numbers cited inline.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

// ── SLH-DSA-SHA2-128s parameters (FIPS 205 Table 2) ─────────────────────────

/// Security parameter / hash output length in bytes.
pub const N: usize = 16;
/// Total hypertree height.
pub const H: usize = 63;
/// Number of hypertree layers.
pub const D: usize = 7;
/// Height of each XMSS subtree (h′ = h/d).
pub const HP: usize = 9;
/// FORS tree height.
pub const A: usize = 12;
/// Number of FORS trees.
pub const K: usize = 14;
/// Winternitz parameter lg(w).
pub const LG_W: u6 = 4;
/// Winternitz w = 2^lg_w.
pub const W: u32 = 16;
/// Message-digest length H_msg produces, in bytes.
pub const M_DIGEST: usize = 30;

/// WOTS+ length-1 (⌈8n / lg_w⌉).
pub const LEN1: usize = 32;
/// WOTS+ length-2 (checksum chains).
pub const LEN2: usize = 3;
/// WOTS+ total chain count.
pub const LEN: usize = LEN1 + LEN2;

/// Encoded public-key length (PK.seed ‖ PK.root).
pub const public_key_len: usize = 2 * N;
/// Encoded signature length (R ‖ SIG_FORS ‖ SIG_HT).
pub const signature_len: usize = (1 + K * (1 + A) + H + D * LEN) * N;

/// Per-tree FORS signature stride: SK value + a authentication nodes.
const fors_tree_stride: usize = (A + 1) * N;
/// FORS signature length: k trees.
const sig_fors_len: usize = K * fors_tree_stride;
/// Per-layer XMSS signature stride: WOTS+ sig + h′ authentication nodes.
const xmss_sig_stride: usize = (LEN + HP) * N;
/// Hypertree signature length: d XMSS layers.
const sig_ht_len: usize = D * xmss_sig_stride;

comptime {
    // Structural byte-length invariants derived independently of `signature_len`,
    // so a mistyped parameter is caught at compile time rather than by a KAT.
    std.debug.assert(public_key_len == 32);
    std.debug.assert(sig_fors_len == 2912);
    std.debug.assert(sig_ht_len == 4928);
    std.debug.assert(N + sig_fors_len + sig_ht_len == signature_len);
    std.debug.assert(signature_len == 7856);
    std.debug.assert(LEN == 35);
    // m = ⌈k·a/8⌉ + ⌈(h − h/d)/8⌉ + ⌈h/(8d)⌉.
    std.debug.assert(md_len + idx_tree_bytes + idx_leaf_bytes == M_DIGEST);
}

/// ADRS type constants (FIPS 205 §4.2).
const AdrsType = struct {
    const wots_hash: u32 = 0;
    const wots_pk: u32 = 1;
    const tree: u32 = 2;
    const fors_tree: u32 = 3;
    const fors_roots: u32 = 4;
};

// ── ADRS: 32-byte address with SHA-2 22-byte compression (§4.2, §11.2) ───────

/// The address is a fixed 32-byte array of eight big-endian 32-bit words:
///   word 0     layer address        (bytes  0.. 4)
///   words 1-3  tree address (96-bit) (bytes  4..16)
///   word 4     type                  (bytes 16..20)
///   words 5-7  type-specific         (bytes 20..32)
const Adrs = [32]u8;

inline fn writeU32be(a: *Adrs, off: usize, v: u32) void {
    std.mem.writeInt(u32, a[off..][0..4], v, .big);
}

inline fn readU32be(a: Adrs, off: usize) u32 {
    return std.mem.readInt(u32, a[off..][0..4], .big);
}

inline fn setLayerAddr(a: *Adrs, layer: u32) void {
    writeU32be(a, 0, layer);
}

/// Tree address is 96-bit; idx_tree here is < 2^54, so the high word is zero.
inline fn setTreeAddr(a: *Adrs, t: u64) void {
    writeU32be(a, 4, 0);
    std.mem.writeInt(u64, a[8..16], t, .big);
}

/// setTypeAndClear(Y): set the type word and zero the final 12 bytes.
inline fn setType(a: *Adrs, ty: u32) void {
    writeU32be(a, 16, ty);
    @memset(a[20..32], 0);
}

inline fn setKeyPairAddr(a: *Adrs, i: u32) void {
    writeU32be(a, 20, i);
}

inline fn getKeyPairAddr(a: Adrs) u32 {
    return readU32be(a, 20);
}

/// setChainAddress and setTreeHeight share word 6 (bytes 24..28).
inline fn setChainAddr(a: *Adrs, i: u32) void {
    writeU32be(a, 24, i);
}

inline fn setTreeHeight(a: *Adrs, i: u32) void {
    writeU32be(a, 24, i);
}

/// setHashAddress and setTreeIndex share word 7 (bytes 28..32).
inline fn setHashAddr(a: *Adrs, i: u32) void {
    writeU32be(a, 28, i);
}

inline fn setTreeIndex(a: *Adrs, i: u32) void {
    writeU32be(a, 28, i);
}

inline fn getTreeIndex(a: Adrs) u32 {
    return readU32be(a, 28);
}

/// ADRS^c (SHA-2 compressed address, 22 bytes):
///   ADRS[3] ‖ ADRS[8:16] ‖ ADRS[19] ‖ ADRS[20:32].
inline fn compressAdrs(a: Adrs) [22]u8 {
    var c: [22]u8 = undefined;
    c[0] = a[3];
    @memcpy(c[1..9], a[8..16]);
    c[9] = a[19];
    @memcpy(c[10..22], a[20..32]);
    return c;
}

// ── Tweakable hash F/H/T_ℓ (SHA-256, midstate-cloned prefix) ─────────────────

const zeros48: [48]u8 = @splat(0);

/// Holds the SHA-256 midstate after absorbing `PK.seed ‖ toByte(0,48)` (exactly
/// one 64-byte block). Every F/H/T_ℓ call clones the midstate and continues with
/// `ADRS^c ‖ M`, then truncates to n bytes.
const TweakHash = struct {
    base: Sha256,

    fn init(pk_seed: []const u8) TweakHash {
        var s = Sha256.init(.{});
        s.update(pk_seed); // n = 16 bytes
        s.update(&zeros48); // → 64-byte block boundary
        return .{ .base = s };
    }

    /// Trunc_n(SHA-256(PK.seed ‖ toByte(0,48) ‖ ADRS^c ‖ msg)). `msg` is the
    /// pre-concatenated tweakable-hash input (n, 2n, k·n, or len·n bytes).
    fn hash(self: TweakHash, adrs: Adrs, msg: []const u8) [N]u8 {
        var s = self.base; // clone midstate (plain value struct)
        const c = compressAdrs(adrs);
        s.update(&c);
        s.update(msg);
        var digest: [32]u8 = undefined;
        s.final(&digest);
        return digest[0..N].*;
    }
};

// ── H_msg via MGF1-SHA-256 (§11.2.1) ────────────────────────────────────────

/// MGF1 with SHA-256 (RFC 8017): out = ‖_c SHA-256(seed_parts ‖ toByte(c,4)).
fn mgf1Sha256(seed_parts: []const []const u8, out: []u8) void {
    var counter: u32 = 0;
    var pos: usize = 0;
    while (pos < out.len) {
        var s = Sha256.init(.{});
        for (seed_parts) |p| s.update(p);
        var cbytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &cbytes, counter, .big);
        s.update(&cbytes);
        var block: [32]u8 = undefined;
        s.final(&block);
        const take = @min(block.len, out.len - pos);
        @memcpy(out[pos .. pos + take], block[0..take]);
        pos += take;
        counter += 1;
    }
}

/// H_msg(R, PK.seed, PK.root, M) → m-byte digest. The message `m_parts` are
/// concatenated in place so no large M′ is materialized.
fn hMsg(
    r: []const u8,
    pk_seed: []const u8,
    pk_root: []const u8,
    m_parts: []const []const u8,
    out: *[M_DIGEST]u8,
) void {
    var s = Sha256.init(.{});
    s.update(r);
    s.update(pk_seed);
    s.update(pk_root);
    for (m_parts) |p| s.update(p);
    var inner: [32]u8 = undefined;
    s.final(&inner);
    mgf1Sha256(&.{ r, pk_seed, &inner }, out);
}

// ── base_2^b (FIPS 205 Algorithm 4, MSB-first) ──────────────────────────────

/// Convert `x` into `out.len` integers, each `b` bits, MSB-first. Consumes
/// ⌈out.len·b / 8⌉ bytes of `x`; the caller guarantees `x` is long enough.
fn base2b(x: []const u8, comptime b: u6, out: []u32) void {
    var in: usize = 0;
    var bits: u6 = 0;
    var total: u32 = 0;
    const mask: u32 = (@as(u32, 1) << b) - 1;
    for (out) |*o| {
        while (bits < b) {
            total = (total << 8) | x[in];
            in += 1;
            bits += 8;
        }
        bits -= b;
        o.* = (total >> @intCast(bits)) & mask;
    }
}

/// Big-endian byte string → integer (up to 8 bytes).
fn toIntBE(bytes: []const u8) u64 {
    var v: u64 = 0;
    for (bytes) |b| v = (v << 8) | b;
    return v;
}

// ── WOTS+ (Algorithms 5, 8) ─────────────────────────────────────────────────

/// chain(X, i, s): apply F for `s` steps starting at chain position `i`.
fn chain(x: [N]u8, start: u32, steps: u32, th: TweakHash, adrs: *Adrs) [N]u8 {
    var tmp = x;
    var j = start;
    while (j < start + steps) : (j += 1) {
        setHashAddr(adrs, j);
        tmp = th.hash(adrs.*, &tmp);
    }
    return tmp;
}

/// Expand the WOTS+ message `m` (n bytes) into `len` base-w chain lengths,
/// including the len2 checksum chains (FIPS 205 Algorithm 8, steps 1-6).
fn wotsChainLengths(m: [N]u8) [LEN]u32 {
    var msg: [LEN]u32 = undefined;
    base2b(&m, LG_W, msg[0..LEN1]);
    var csum: u32 = 0;
    for (msg[0..LEN1]) |mi| csum += W - 1 - mi; // ≤ 32·15 = 480
    // csum ← csum << ((8 − ((len2·lg_w) mod 8)) mod 8).
    const shift: u6 = @intCast((8 - ((LEN2 * @as(usize, LG_W)) % 8)) % 8);
    csum <<= shift;
    // toByte(csum, ⌈len2·lg_w / 8⌉ = 2) then base_2^b to len2 chains.
    var csum_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &csum_bytes, @intCast(csum), .big);
    base2b(&csum_bytes, LG_W, msg[LEN1..LEN]);
    return msg;
}

/// wots_pkFromSig: recover the WOTS+ public key from a signature (Algorithm 8).
fn wotsPkFromSig(sig: []const u8, m: [N]u8, th: TweakHash, adrs: *Adrs) [N]u8 {
    const msg = wotsChainLengths(m);
    var pk_buf: [LEN * N]u8 = undefined;
    for (0..LEN) |i| {
        setChainAddr(adrs, @intCast(i));
        const start = msg[i];
        const chained = chain(sig[i * N ..][0..N].*, start, W - 1 - start, th, adrs);
        @memcpy(pk_buf[i * N ..][0..N], &chained);
    }
    var pk_adrs = adrs.*;
    setType(&pk_adrs, AdrsType.wots_pk);
    setKeyPairAddr(&pk_adrs, getKeyPairAddr(adrs.*));
    return th.hash(pk_adrs, &pk_buf);
}

// ── XMSS (Algorithm 10) ─────────────────────────────────────────────────────

/// xmss_pkFromSig: recover an XMSS root from (WOTS+ sig ‖ AUTH) and a leaf `idx`.
fn xmssPkFromSig(idx: u32, sig_xmss: []const u8, m: [N]u8, th: TweakHash, adrs: *Adrs) [N]u8 {
    setType(adrs, AdrsType.wots_hash);
    setKeyPairAddr(adrs, idx);
    const wots_sig = sig_xmss[0 .. LEN * N];
    const auth = sig_xmss[LEN * N ..][0 .. HP * N];

    var node = wotsPkFromSig(wots_sig, m, th, adrs);

    setType(adrs, AdrsType.tree);
    setTreeIndex(adrs, idx);
    for (0..HP) |kk| {
        setTreeHeight(adrs, @intCast(kk + 1));
        const auth_k = auth[kk * N ..][0..N];
        var buf: [2 * N]u8 = undefined;
        if ((idx >> @intCast(kk)) & 1 == 0) {
            setTreeIndex(adrs, getTreeIndex(adrs.*) / 2);
            @memcpy(buf[0..N], &node);
            @memcpy(buf[N..], auth_k);
        } else {
            setTreeIndex(adrs, (getTreeIndex(adrs.*) - 1) / 2);
            @memcpy(buf[0..N], auth_k);
            @memcpy(buf[N..], &node);
        }
        node = th.hash(adrs.*, &buf);
    }
    return node;
}

// ── Hypertree verify (Algorithm 19) ─────────────────────────────────────────

fn htVerify(
    m: [N]u8,
    sig_ht: []const u8,
    th: TweakHash,
    idx_tree_init: u64,
    idx_leaf_init: u32,
    pk_root: []const u8,
) bool {
    var adrs: Adrs = @splat(0);
    var idx_tree = idx_tree_init;
    setTreeAddr(&adrs, idx_tree);

    var node = xmssPkFromSig(idx_leaf_init, sig_ht[0..xmss_sig_stride], m, th, &adrs);

    const leaf_mask: u64 = (@as(u64, 1) << @intCast(HP)) - 1;
    for (1..D) |j| {
        const idx_leaf: u32 = @intCast(idx_tree & leaf_mask);
        idx_tree >>= @intCast(HP);
        setLayerAddr(&adrs, @intCast(j));
        setTreeAddr(&adrs, idx_tree);
        const off = j * xmss_sig_stride;
        node = xmssPkFromSig(idx_leaf, sig_ht[off..][0..xmss_sig_stride], node, th, &adrs);
    }
    return ctEqual(&node, pk_root);
}

// ── FORS verify (Algorithm 17) ──────────────────────────────────────────────

/// fors_pkFromSig: recover the FORS public key (n bytes) from the FORS
/// signature and the k·a-bit message digest `md`.
fn forsPkFromSig(sig_fors: []const u8, md: []const u8, th: TweakHash, adrs: *Adrs) [N]u8 {
    var indices: [K]u32 = undefined;
    base2b(md, A, &indices);

    var roots: [K * N]u8 = undefined;
    for (0..K) |i| {
        const tree = sig_fors[i * fors_tree_stride ..][0..fors_tree_stride];
        const sk = tree[0..N];
        const auth = tree[N .. N + A * N];

        setTreeHeight(adrs, 0);
        setTreeIndex(adrs, @intCast(i * (@as(usize, 1) << A) + indices[i]));
        var node = th.hash(adrs.*, sk); // F(PK.seed, ADRS, sk)

        for (0..A) |j| {
            setTreeHeight(adrs, @intCast(j + 1));
            const auth_j = auth[j * N ..][0..N];
            var buf: [2 * N]u8 = undefined;
            if ((indices[i] >> @intCast(j)) & 1 == 0) {
                setTreeIndex(adrs, getTreeIndex(adrs.*) / 2);
                @memcpy(buf[0..N], &node);
                @memcpy(buf[N..], auth_j);
            } else {
                setTreeIndex(adrs, (getTreeIndex(adrs.*) - 1) / 2);
                @memcpy(buf[0..N], auth_j);
                @memcpy(buf[N..], &node);
            }
            node = th.hash(adrs.*, &buf);
        }
        @memcpy(roots[i * N ..][0..N], &node);
    }

    var pk_adrs = adrs.*;
    setType(&pk_adrs, AdrsType.fors_roots);
    setKeyPairAddr(&pk_adrs, getKeyPairAddr(adrs.*));
    return th.hash(pk_adrs, &roots); // T_k(PK.seed, forspkADRS, roots)
}

// ── Message-digest field widths (Algorithm 20 steps 7-11) ───────────────────

/// ⌈k·a / 8⌉ bytes of message index material.
const md_len: usize = (K * A + 7) / 8; // 21
/// ⌈(h − h/d) / 8⌉ bytes for the tree index.
const idx_tree_bytes: usize = ((H - HP) + 7) / 8; // 7
/// ⌈h / (8·d)⌉ bytes for the leaf index.
const idx_leaf_bytes: usize = (H + 8 * D - 1) / (8 * D); // 2

// ── Verify ──────────────────────────────────────────────────────────────────

/// `slh_verify_internal(M, SIG, PK)` for SLH-DSA-SHA2-128s (FIPS 205
/// Algorithm 20). `m_parts` is the internal message provided as an ordered set
/// of slices concatenated in place. Returns `true` on a valid signature, `false`
/// on any structural or cryptographic failure. Never errors, never panics on
/// attacker-controlled input.
fn verifyInternalParts(pk: []const u8, m_parts: []const []const u8, sig: []const u8) bool {
    if (pk.len != public_key_len) return false;
    if (sig.len != signature_len) return false;

    const pk_seed = pk[0..N];
    const pk_root = pk[N .. 2 * N];

    const r = sig[0..N];
    const sig_fors = sig[N .. N + sig_fors_len];
    const sig_ht = sig[N + sig_fors_len ..][0..sig_ht_len];

    var digest: [M_DIGEST]u8 = undefined;
    hMsg(r, pk_seed, pk_root, m_parts, &digest);

    const md = digest[0..md_len];
    const idx_tree = toIntBE(digest[md_len .. md_len + idx_tree_bytes]) &
        ((@as(u64, 1) << @intCast(H - HP)) - 1);
    const idx_leaf: u32 = @intCast(toIntBE(digest[md_len + idx_tree_bytes ..][0..idx_leaf_bytes]) &
        ((@as(u64, 1) << @intCast(HP)) - 1));

    const th = TweakHash.init(pk_seed);

    var adrs: Adrs = @splat(0);
    setTreeAddr(&adrs, idx_tree);
    setType(&adrs, AdrsType.fors_tree);
    setKeyPairAddr(&adrs, idx_leaf);

    const pk_fors = forsPkFromSig(sig_fors, md, th, &adrs);
    return htVerify(pk_fors, sig_ht, th, idx_tree, idx_leaf, pk_root);
}

/// `slh_verify_internal` over a single contiguous internal message.
pub fn verifyInternal(pk: []const u8, m_prime: []const u8, sig: []const u8) bool {
    return verifyInternalParts(pk, &.{m_prime}, sig);
}

/// `slh_verify(M, ctx, SIG, PK)` for SLH-DSA-SHA2-128s (FIPS 205 Algorithm 24),
/// pure (non-prehashed) variant. `ctx` is the context string (empty for X.509
/// certificate signatures per draft-ietf-lamps-x509-slhdsa). Returns `false` on
/// any failure, including `ctx.len > 255`.
pub fn verify(pk: []const u8, msg: []const u8, ctx: []const u8, sig: []const u8) bool {
    if (ctx.len > 255) return false;
    // M′ = toByte(0,1) ‖ toByte(|ctx|,1) ‖ ctx ‖ M.
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

test "slh-dsa-sha2-128s parameter and structural self-consistency" {
    // Cheap invariants that would surface a mistyped constant before the
    // (expensive) KAT runs. Independent published-vector KATs live in
    // slh_dsa_kat.zig.
    try std.testing.expectEqual(@as(usize, 32), public_key_len);
    try std.testing.expectEqual(@as(usize, 7856), signature_len);
    try std.testing.expectEqual(@as(usize, 21), md_len);
    try std.testing.expectEqual(@as(usize, 7), idx_tree_bytes);
    try std.testing.expectEqual(@as(usize, 2), idx_leaf_bytes);

    // base_2^b MSB-first spot check: 0xAB, 0xCD as three 4-bit nibbles → A,B,C.
    var out3: [3]u32 = undefined;
    base2b(&[_]u8{ 0xAB, 0xCD }, 4, &out3);
    try std.testing.expectEqual(@as(u32, 0xA), out3[0]);
    try std.testing.expectEqual(@as(u32, 0xB), out3[1]);
    try std.testing.expectEqual(@as(u32, 0xC), out3[2]);

    // Compressed-ADRS field selection.
    var a: Adrs = @splat(0);
    setLayerAddr(&a, 6);
    setTreeAddr(&a, 0x0102030405);
    setType(&a, AdrsType.fors_tree);
    setKeyPairAddr(&a, 0x11223344);
    const c = compressAdrs(a);
    try std.testing.expectEqual(@as(u8, 6), c[0]); // ADRS[3] = layer LSB
    try std.testing.expectEqual(@as(u8, 3), c[9]); // ADRS[19] = type LSB (fors_tree)
    try std.testing.expectEqual(@as(u8, 0x11), c[10]); // ADRS[20] = keypair MSB

    // Structural rejects: wrong-length pk / sig fail closed without panicking.
    const pk: [public_key_len]u8 = @splat(0);
    const sig: [signature_len]u8 = @splat(0);
    try std.testing.expect(!verifyInternal(pk[0 .. public_key_len - 1], "m", &sig));
    try std.testing.expect(!verifyInternal(&pk, "m", sig[0 .. signature_len - 1]));
    // Over-length context rejected before any hashing.
    const big_ctx: [256]u8 = @splat(0);
    try std.testing.expect(!verify(&pk, "m", &big_ctx, &sig));
}
