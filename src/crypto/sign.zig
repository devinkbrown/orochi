//! Ed25519 signatures for Mizuchi identity and authorization boundaries.
//!
//! This module wraps Zig 0.16's `std.crypto.sign.Ed25519` key/public/signature
//! encodings while keeping private key material behind `Secret(T)`. Signing is
//! deterministic RFC 8032 Ed25519, with a zero-allocation domain-separated path
//! for Suimyaku/MeshPass uses where signatures must not be reusable across
//! node identity, capability token, and operator challenge contexts.
const std = @import("std");
const Secret = @import("secret.zig").Secret;

const StdEd25519 = std.crypto.sign.Ed25519;
const Curve = StdEd25519.Curve;
const Sha512 = std.crypto.hash.sha2.Sha512;

pub const public_key_len = StdEd25519.PublicKey.encoded_length;
pub const secret_key_len = StdEd25519.SecretKey.encoded_length;
pub const seed_len = StdEd25519.KeyPair.seed_length;
pub const signature_len = StdEd25519.Signature.encoded_length;

pub const PublicKey = [public_key_len]u8;
pub const Signature = [signature_len]u8;
pub const Seed = [seed_len]u8;
pub const SecretKey = Secret([secret_key_len]u8);

pub const SignError = std.crypto.errors.IdentityElementError ||
    std.crypto.errors.KeyMismatchError ||
    std.crypto.errors.NonCanonicalError ||
    std.crypto.errors.WeakPublicKeyError;

pub const VerifyError = StdEd25519.Signature.VerifyError;

const domain_prefix_magic = "mizuchi-ed25519ctx-v1";

/// Ed25519 key pair. `secret_key` is seed || public key, matching std/RFC
/// Ed25519 storage, and is wiped by `deinit`.
pub const KeyPair = struct {
    public_key: PublicKey,
    secret_key: SecretKey,

    /// Generate a new key pair using the caller-provided Zig 0.16 `std.Io`
    /// randomness source.
    pub fn generate(io: std.Io) KeyPair {
        var kp = StdEd25519.KeyPair.generate(io);
        defer secureZero(std.mem.asBytes(&kp.secret_key));
        return .{
            .public_key = kp.public_key.toBytes(),
            .secret_key = SecretKey.init(kp.secret_key.toBytes()),
        };
    }

    /// Deterministically derive a key pair from a 32-byte Ed25519 seed.
    pub fn fromSeed(seed: Seed) std.crypto.errors.IdentityElementError!KeyPair {
        var kp = try StdEd25519.KeyPair.generateDeterministic(seed);
        defer secureZero(std.mem.asBytes(&kp.secret_key));
        return .{
            .public_key = kp.public_key.toBytes(),
            .secret_key = SecretKey.init(kp.secret_key.toBytes()),
        };
    }

    /// Zeroize the wrapped private key material.
    pub fn deinit(self: *KeyPair) void {
        self.secret_key.wipe();
    }

    /// Sign `msg` with plain RFC 8032 Ed25519.
    pub fn sign(self: *const KeyPair, msg: []const u8) SignError!Signature {
        return self.signPrefixed("", msg);
    }

    /// Sign `msg` under a compile-time domain label.
    ///
    /// The domain is length-framed into the signed transcript:
    /// `magic || len(domain) || domain || msg`.
    pub fn signCtx(
        self: *const KeyPair,
        comptime domain: []const u8,
        msg: []const u8,
    ) SignError!Signature {
        const prefix = domainPrefix(domain);
        return self.signPrefixed(&prefix, msg);
    }

    fn signPrefixed(
        self: *const KeyPair,
        prefix: []const u8,
        msg: []const u8,
    ) SignError!Signature {
        var sk_bytes = self.secret_key.declassify();
        defer secureZero(&sk_bytes);

        if (!std.mem.eql(u8, sk_bytes[seed_len..], self.public_key[0..])) {
            return error.KeyMismatch;
        }

        const seed = sk_bytes[0..seed_len].*;
        const public_key = sk_bytes[seed_len..].*;

        var expanded: [Sha512.digest_length]u8 = undefined;
        defer secureZero(&expanded);
        var seed_hash = Sha512.init(.{});
        seed_hash.update(&seed);
        seed_hash.final(&expanded);

        var scalar = expanded[0..32].*;
        defer secureZero(&scalar);
        Curve.scalar.clamp(&scalar);

        var nonce64: [Sha512.digest_length]u8 = undefined;
        defer secureZero(&nonce64);
        var nonce_hash = Sha512.init(.{});
        nonce_hash.update(expanded[32..]);
        nonce_hash.update(prefix);
        nonce_hash.update(msg);
        nonce_hash.final(&nonce64);

        var nonce = Curve.scalar.reduce64(nonce64);
        defer secureZero(&nonce);

        const r = try Curve.basePoint.mul(nonce);
        const r_bytes = r.toBytes();

        var challenge64: [Sha512.digest_length]u8 = undefined;
        defer secureZero(&challenge64);
        var challenge_hash = Sha512.init(.{});
        challenge_hash.update(&r_bytes);
        challenge_hash.update(&public_key);
        challenge_hash.update(prefix);
        challenge_hash.update(msg);
        challenge_hash.final(&challenge64);

        const challenge = Curve.scalar.reduce64(challenge64);
        const s = Curve.scalar.mulAdd(challenge, scalar, nonce);

        var out: Signature = undefined;
        out[0..Curve.encoded_length].* = r_bytes;
        out[Curve.encoded_length..].* = s;
        return out;
    }
};

/// Verify a plain RFC 8032 Ed25519 signature.
pub fn verify(msg: []const u8, sig: Signature, public_key: PublicKey) VerifyError!bool {
    return verifyPrefixed("", msg, sig, public_key);
}

/// Verify a domain-separated Ed25519 signature created by `KeyPair.signCtx`.
pub fn verifyCtx(
    comptime domain: []const u8,
    msg: []const u8,
    sig: Signature,
    public_key: PublicKey,
) VerifyError!bool {
    const prefix = domainPrefix(domain);
    return verifyPrefixed(&prefix, msg, sig, public_key);
}

fn verifyPrefixed(
    prefix: []const u8,
    msg: []const u8,
    sig: Signature,
    public_key: PublicKey,
) VerifyError!bool {
    const pk = try StdEd25519.PublicKey.fromBytes(public_key);
    const std_sig = StdEd25519.Signature.fromBytes(sig);

    var verifier = try std_sig.verifier(pk);
    verifier.update(prefix);
    verifier.update(msg);
    verifier.verify() catch |err| switch (err) {
        error.SignatureVerificationFailed => return false,
        else => return err,
    };
    return true;
}

fn domainPrefix(comptime domain: []const u8) [domain_prefix_magic.len + 1 + domain.len]u8 {
    comptime {
        if (domain.len == 0) @compileError("Ed25519 domain label must not be empty");
        if (domain.len > std.math.maxInt(u8)) @compileError("Ed25519 domain label exceeds 255 bytes");
    }

    var out: [domain_prefix_magic.len + 1 + domain.len]u8 = undefined;
    @memcpy(out[0..domain_prefix_magic.len], domain_prefix_magic);
    out[domain_prefix_magic.len] = @intCast(domain.len);
    @memcpy(out[domain_prefix_magic.len + 1 ..], domain);
    return out;
}

fn secureZero(buf: []u8) void {
    for (buf) |*b| {
        const vp: *volatile u8 = @ptrCast(b);
        vp.* = 0;
    }
}

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "RFC 8032 Ed25519 test vector 1" {
    var kp = try KeyPair.fromSeed(hex("9d61b19deffd5a60ba844af492ec2cc4" ++
        "4449c5697b326919703bac031cae7f60"));
    defer kp.deinit();

    try std.testing.expectEqualSlices(
        u8,
        &hex("d75a980182b10ab7d54bfed3c964073a" ++
            "0ee172f3daa62325af021a68f707511a"),
        &kp.public_key,
    );

    const sig = try kp.sign("");
    try std.testing.expectEqualSlices(
        u8,
        &hex("e5564300c360ac729086e2cc806e828a" ++
            "84877f1eb8e5d974d873e06522490155" ++
            "5fb8821590a33bacc61e39701cf9b46b" ++
            "d25bf5f0595bbe24655141438e7a100b"),
        &sig,
    );
    try std.testing.expect(try verify("", sig, kp.public_key));
}

test "RFC 8032 Ed25519 test vector 2" {
    var kp = try KeyPair.fromSeed(hex("4ccd089b28ff96da9db6c346ec114e0f" ++
        "5b8a319f35aba624da8cf6ed4fb8a6fb"));
    defer kp.deinit();

    const msg = hex("72");
    const sig = try kp.sign(&msg);

    try std.testing.expectEqualSlices(
        u8,
        &hex("92a009a9f0d4cab8720e820b5f642540" ++
            "a2b27b5416503f8fb3762223ebdb69da" ++
            "085ac1e43e15996e458f3613d0f11d8c" ++
            "387b2eaeb4302aeeb00d291612bb0c00"),
        &sig,
    );
    try std.testing.expect(try verify(&msg, sig, kp.public_key));
}

test "tampered signature is rejected" {
    var kp = try KeyPair.fromSeed(hex("9d61b19deffd5a60ba844af492ec2cc4" ++
        "4449c5697b326919703bac031cae7f60"));
    defer kp.deinit();

    var sig = try kp.sign("mizuchi");
    sig[32] ^= 0x01;

    try std.testing.expect(!try verify("mizuchi", sig, kp.public_key));
}

test "domain separation prevents cross-use" {
    var kp = try KeyPair.fromSeed(hex("4ccd089b28ff96da9db6c346ec114e0f" ++
        "5b8a319f35aba624da8cf6ed4fb8a6fb"));
    defer kp.deinit();

    const msg = "same transcript bytes";
    const node_sig = try kp.signCtx("node-identity", msg);
    const cap_sig = try kp.signCtx("capability-token", msg);

    try std.testing.expect(!std.mem.eql(u8, &node_sig, &cap_sig));
    try std.testing.expect(try verifyCtx("node-identity", msg, node_sig, kp.public_key));
    try std.testing.expect(try verifyCtx("capability-token", msg, cap_sig, kp.public_key));
    try std.testing.expect(!try verifyCtx("capability-token", msg, node_sig, kp.public_key));
    try std.testing.expect(!try verify(msg, node_sig, kp.public_key));
}

test {
    std.testing.refAllDecls(@This());
}
