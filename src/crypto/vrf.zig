//! Verifiable Random Function over Edwards25519 + SHA-512.
//!
//! NOTE: this is a BESPOKE Mizuchi VRF, NOT RFC 9381 ECVRF. It is internally
//! consistent (prove/verify round-trip, deterministic beta, tamper-rejecting)
//! and suitable for closed-mesh leader election, but it deliberately differs
//! from RFC 9381 — custom suite string, a 128-bit challenge, hash-to-curve via
//! plain try-and-increment, and a different challenge-generation point order
//! without the spec's domain-separation octets. Do NOT treat its output as a
//! standards-compliant ECVRF or expect interop with RFC 9381 implementations.
const std = @import("std");

const Sha512 = std.crypto.hash.sha2.Sha512;
const Curve = std.crypto.ecc.Edwards25519;
const Scalar = Curve.scalar.CompressedScalar;

pub const Seed = [32]u8;
pub const PublicKey = [Curve.encoded_length]u8;
pub const Beta = [Sha512.digest_length]u8;

pub const Proof = struct {
    pub const challenge_length = 16;
    pub const encoded_length = Curve.encoded_length + challenge_length + @sizeOf(Scalar);

    gamma: [Curve.encoded_length]u8,
    c: [challenge_length]u8,
    s: Scalar,

    pub fn toBytes(self: Proof) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        out[0..32].* = self.gamma;
        out[32..48].* = self.c;
        out[48..80].* = self.s;
        return out;
    }

    pub fn fromBytes(bytes: [encoded_length]u8) Proof {
        return .{
            .gamma = bytes[0..32].*,
            .c = bytes[32..48].*,
            .s = bytes[48..80].*,
        };
    }
};

const ExpandedSecret = struct {
    scalar: Scalar,
    prefix: [32]u8,
};

pub fn publicKey(seed: Seed) !PublicKey {
    const secret = expandSeed(seed);
    const y = try Curve.basePoint.mul(secret.scalar);
    return y.toBytes();
}

pub fn prove(seed: Seed, alpha: []const u8) !Proof {
    const secret = expandSeed(seed);
    const y = try Curve.basePoint.mul(secret.scalar);
    const pk = y.toBytes();
    const h = try hashToCurve(pk, alpha);
    const gamma = try h.mul(secret.scalar);
    const k = nonce(secret.prefix, h.toBytes());
    const u = try Curve.basePoint.mul(k);
    const v = try h.mul(k);
    const c = challenge(h, gamma, u, v, pk);
    const s = Curve.scalar.mulAdd(cToScalar(c), secret.scalar, k);

    return .{ .gamma = gamma.toBytes(), .c = c, .s = s };
}

pub fn verify(pk: PublicKey, alpha: []const u8, proof: Proof) ?Beta {
    Curve.rejectNonCanonical(pk) catch return null;
    const y = Curve.fromBytes(pk) catch return null;
    y.rejectIdentity() catch return null;
    y.rejectUnexpectedSubgroup() catch return null;

    Curve.rejectNonCanonical(proof.gamma) catch return null;
    const gamma = Curve.fromBytes(proof.gamma) catch return null;
    gamma.rejectIdentity() catch return null;
    gamma.rejectUnexpectedSubgroup() catch return null;
    Curve.scalar.rejectNonCanonical(proof.s) catch return null;

    const h = hashToCurve(pk, alpha) catch return null;
    const c_scalar = cToScalar(proof.c);
    const u = Curve.basePoint.mulDoubleBasePublic(proof.s, y.neg(), c_scalar) catch return null;
    const v = h.mulDoubleBasePublic(proof.s, gamma.neg(), c_scalar) catch return null;
    const expected_c = challenge(h, gamma, u, v, pk);
    if (!std.mem.eql(u8, proof.c[0..], expected_c[0..])) return null;

    return betaFromGamma(gamma);
}

pub fn proofToHash(proof: Proof) ?Beta {
    Curve.rejectNonCanonical(proof.gamma) catch return null;
    const gamma = Curve.fromBytes(proof.gamma) catch return null;
    gamma.rejectIdentity() catch return null;
    gamma.rejectUnexpectedSubgroup() catch return null;
    return betaFromGamma(gamma);
}

fn expandSeed(seed: Seed) ExpandedSecret {
    var az: [Sha512.digest_length]u8 = undefined;
    var h = Sha512.init(.{});
    h.update(&seed);
    h.final(&az);

    var scalar = az[0..32].*;
    Curve.scalar.clamp(&scalar);
    return .{ .scalar = scalar, .prefix = az[32..64].* };
}

fn hashToCurve(pk: PublicKey, alpha: []const u8) !Curve {
    var ctr: u16 = 0;
    while (ctr <= 255) : (ctr += 1) {
        var digest: [Sha512.digest_length]u8 = undefined;
        var h = Sha512.init(.{});
        h.update("Mizuchi-ECVRF-Edwards25519-SHA512-TAI:H2C");
        h.update(&pk);
        h.update(alpha);
        h.update(&.{@as(u8, @intCast(ctr))});
        h.final(&digest);

        const encoded = digest[0..32].*;
        Curve.rejectNonCanonical(encoded) catch continue;
        const p = Curve.fromBytes(encoded) catch continue;
        const q = p.clearCofactor();
        q.rejectIdentity() catch continue;
        return q;
    }
    return error.HashToCurveFailed;
}

fn nonce(prefix: [32]u8, h_bytes: [Curve.encoded_length]u8) Scalar {
    var digest: [Sha512.digest_length]u8 = undefined;
    var h = Sha512.init(.{});
    h.update("Mizuchi-ECVRF-Edwards25519-SHA512-TAI:nonce");
    h.update(&prefix);
    h.update(&h_bytes);
    h.final(&digest);
    return Curve.scalar.reduce64(digest);
}

fn challenge(h: Curve, gamma: Curve, u: Curve, v: Curve, pk: PublicKey) [Proof.challenge_length]u8 {
    var digest: [Sha512.digest_length]u8 = undefined;
    var st = Sha512.init(.{});
    st.update("Mizuchi-ECVRF-Edwards25519-SHA512-TAI:challenge");
    st.update(&pk);
    updatePoint(&st, h);
    updatePoint(&st, gamma);
    updatePoint(&st, u);
    updatePoint(&st, v);
    st.final(&digest);
    return digest[0..Proof.challenge_length].*;
}

fn updatePoint(st: *Sha512, p: Curve) void {
    const encoded = p.toBytes();
    st.update(&encoded);
}

fn cToScalar(c: [Proof.challenge_length]u8) Scalar {
    var out = [_]u8{0} ** 32;
    out[0..Proof.challenge_length].* = c;
    return out;
}

fn betaFromGamma(gamma: Curve) Beta {
    var beta: Beta = undefined;
    var h = Sha512.init(.{});
    h.update("Mizuchi-ECVRF-Edwards25519-SHA512-TAI:beta");
    const gamma_bytes = gamma.toBytes();
    h.update(&gamma_bytes);
    h.final(&beta);
    return beta;
}

fn fixedSeed(byte: u8) Seed {
    var seed: Seed = undefined;
    for (&seed, 0..) |*slot, i| {
        slot.* = byte +% @as(u8, @intCast(i * 3));
    }
    return seed;
}

test "prove then verify succeeds and yields beta" {
    const seed = fixedSeed(0x42);
    const alpha = "mizuchi vrf alpha";
    const pk = try publicKey(seed);
    const proof = try prove(seed, alpha);
    const beta = verify(pk, alpha, proof) orelse return error.ExpectedValidProof;
    const direct_beta = proofToHash(proof) orelse return error.ExpectedValidProof;

    try std.testing.expectEqualSlices(u8, direct_beta[0..], beta[0..]);
    try std.testing.expect(!std.mem.eql(u8, beta[0..], (&([_]u8{0} ** Sha512.digest_length))[0..]));
}

test "proof encoding round-trips" {
    const seed = fixedSeed(0x11);
    const alpha = "round-trip alpha";
    const pk = try publicKey(seed);
    const proof = try prove(seed, alpha);
    const encoded = proof.toBytes();
    const decoded = Proof.fromBytes(encoded);

    try std.testing.expectEqualSlices(u8, proof.gamma[0..], decoded.gamma[0..]);
    try std.testing.expectEqualSlices(u8, proof.c[0..], decoded.c[0..]);
    try std.testing.expectEqualSlices(u8, proof.s[0..], decoded.s[0..]);
    try std.testing.expect(verify(pk, alpha, decoded) != null);
}

test "verify rejects a tampered proof, alpha, and public key" {
    const seed = fixedSeed(0x05);
    const other_seed = fixedSeed(0xa0);
    const alpha = "original alpha";
    const pk = try publicKey(seed);
    const proof = try prove(seed, alpha);

    var tampered_proof = proof;
    tampered_proof.s[0] ^= 0x01;
    try std.testing.expect(verify(pk, alpha, tampered_proof) == null);
    try std.testing.expect(verify(pk, "different alpha", proof) == null);

    const other_pk = try publicKey(other_seed);
    try std.testing.expect(verify(other_pk, alpha, proof) == null);
}

test "beta is deterministic for seed and alpha" {
    const seed = fixedSeed(0x7c);
    const alpha = "deterministic alpha";
    const pk = try publicKey(seed);
    const proof_a = try prove(seed, alpha);
    const proof_b = try prove(seed, alpha);
    const beta_a = verify(pk, alpha, proof_a) orelse return error.ExpectedValidProof;
    const beta_b = verify(pk, alpha, proof_b) orelse return error.ExpectedValidProof;

    try std.testing.expectEqualSlices(u8, proof_a.toBytes()[0..], proof_b.toBytes()[0..]);
    try std.testing.expectEqualSlices(u8, beta_a[0..], beta_b[0..]);
}

test "different alpha produces different beta" {
    const seed = fixedSeed(0x28);
    const pk = try publicKey(seed);
    const proof_a = try prove(seed, "alpha one");
    const proof_b = try prove(seed, "alpha two");
    const beta_a = verify(pk, "alpha one", proof_a) orelse return error.ExpectedValidProof;
    const beta_b = verify(pk, "alpha two", proof_b) orelse return error.ExpectedValidProof;

    try std.testing.expect(!std.mem.eql(u8, beta_a[0..], beta_b[0..]));
}

test "tests can build alpha with std.testing allocator" {
    const allocator = std.testing.allocator;
    var alpha: std.ArrayList(u8) = .empty;
    defer alpha.deinit(allocator);
    try alpha.appendSlice(allocator, "allocated ");
    try alpha.appendSlice(allocator, "alpha");

    const seed = fixedSeed(0x91);
    const pk = try publicKey(seed);
    const proof = try prove(seed, alpha.items);
    try std.testing.expect(verify(pk, alpha.items, proof) != null);
}
