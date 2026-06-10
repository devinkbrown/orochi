//! Signed moderation proofs for Orochi policy decisions.
//!
//! A proof is a compact statement that an actor applied an action to a target
//! under a specific policy version and reason digest. The signed bytes are a
//! fixed-order, length-prefixed binary transcript so signatures are stable
//! across machines and process restarts.
const std = @import("std");

const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const PublicKey = [Ed25519.PublicKey.encoded_length]u8;
pub const SecretKey = [Ed25519.SecretKey.encoded_length]u8;
pub const Signature = [Ed25519.Signature.encoded_length]u8;
pub const Digest = [Sha256.digest_length]u8;

pub const max_actor_len: usize = 256;
pub const max_target_len: usize = 256;
pub const max_canonical_len: usize = magic.len + 4 + max_actor_len + 4 + max_target_len + 1 + Sha256.digest_length + 4 + 8 + 8;

const magic = "OROCHI-PROOFMARK-v1";

pub const Proof = struct {
    actor: []const u8,
    target: []const u8,
    action: u8,
    reason_hash: Digest,
    policy_version: u32,
    issued_ms: i64,
    expiry_ms: i64,
};

pub const Error = error{
    ActorTooLong,
    TargetTooLong,
    InvalidTimeWindow,
    BufferTooSmall,
};

pub const EncodeError = Error || std.mem.Allocator.Error;

pub const SignError = Error ||
    std.crypto.errors.IdentityElementError ||
    std.crypto.errors.NonCanonicalError ||
    std.crypto.errors.KeyMismatchError ||
    std.crypto.errors.WeakPublicKeyError ||
    std.crypto.errors.EncodingError;

pub const ReasonHashAlg = enum {
    sha256,
};

pub const reason_hash_alg: ReasonHashAlg = .sha256;

pub fn canonicalLength(proof: Proof) Error!usize {
    try validate(proof);
    return magic.len + 4 + proof.actor.len + 4 + proof.target.len + 1 + Sha256.digest_length + 4 + 8 + 8;
}

pub fn canonicalBytes(proof: Proof, buf: []u8) Error![]const u8 {
    const needed = try canonicalLength(proof);
    if (buf.len < needed) return error.BufferTooSmall;

    var pos: usize = 0;
    copyBytes(buf, &pos, magic);
    writeU32(buf, &pos, @intCast(proof.actor.len));
    copyBytes(buf, &pos, proof.actor);
    writeU32(buf, &pos, @intCast(proof.target.len));
    copyBytes(buf, &pos, proof.target);
    buf[pos] = proof.action;
    pos += 1;
    copyBytes(buf, &pos, &proof.reason_hash);
    writeU32(buf, &pos, proof.policy_version);
    writeI64(buf, &pos, proof.issued_ms);
    writeI64(buf, &pos, proof.expiry_ms);
    return buf[0..pos];
}

pub fn canonicalBytesList(
    proof: Proof,
    allocator: std.mem.Allocator,
    buf: *std.ArrayListUnmanaged(u8),
) EncodeError![]const u8 {
    const needed = try canonicalLength(proof);
    try buf.resize(allocator, needed);
    return canonicalBytes(proof, buf.items);
}

pub fn sign(proof: Proof, secret_key: SecretKey) SignError!Signature {
    var encoded: [max_canonical_len]u8 = undefined;
    const body = try canonicalBytes(proof, &encoded);
    const sk = try Ed25519.SecretKey.fromBytes(secret_key);
    const kp = try Ed25519.KeyPair.fromSecretKey(sk);
    const sig = try kp.sign(body, null);
    return sig.toBytes();
}

pub fn verify(proof: Proof, sig: Signature, public_key: PublicKey) bool {
    var encoded: [max_canonical_len]u8 = undefined;
    const body = canonicalBytes(proof, &encoded) catch return false;
    const pk = Ed25519.PublicKey.fromBytes(public_key) catch return false;
    const signature = Ed25519.Signature.fromBytes(sig);
    signature.verifyStrict(body, pk) catch return false;
    return true;
}

pub fn expired(proof: Proof, now_ms: i64) bool {
    return now_ms >= proof.expiry_ms;
}

pub fn reasonHash(reason_text: []const u8) Digest {
    return switch (reason_hash_alg) {
        .sha256 => blk: {
            var out: Digest = undefined;
            Sha256.hash(reason_text, &out, .{});
            break :blk out;
        },
    };
}

fn validate(proof: Proof) Error!void {
    if (proof.actor.len > max_actor_len) return error.ActorTooLong;
    if (proof.target.len > max_target_len) return error.TargetTooLong;
    if (proof.expiry_ms < proof.issued_ms) return error.InvalidTimeWindow;
}

fn copyBytes(out: []u8, pos: *usize, bytes: []const u8) void {
    @memcpy(out[pos.* .. pos.* + bytes.len], bytes);
    pos.* += bytes.len;
}

fn writeU32(out: []u8, pos: *usize, value: u32) void {
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const shift: u5 = @intCast((3 - i) * 8);
        out[pos.*] = @intCast((value >> shift) & 0xff);
        pos.* += 1;
    }
}

fn writeU64(out: []u8, pos: *usize, value: u64) void {
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const shift: u6 = @intCast((7 - i) * 8);
        out[pos.*] = @intCast((value >> shift) & 0xff);
        pos.* += 1;
    }
}

fn writeI64(out: []u8, pos: *usize, value: i64) void {
    writeU64(out, pos, @bitCast(value));
}

fn testSeed(byte: u8) [Ed25519.KeyPair.seed_length]u8 {
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, byte);
    return seed;
}

fn testKey(byte: u8) !Ed25519.KeyPair {
    return try Ed25519.KeyPair.generateDeterministic(testSeed(byte));
}

fn testProof() Proof {
    return .{
        .actor = "mod:azusa",
        .target = "member:yuki",
        .action = 7,
        .reason_hash = reasonHash("repeat disruptive flood"),
        .policy_version = 14,
        .issued_ms = 1_700_000_000_000,
        .expiry_ms = 1_700_003_600_000,
    };
}

test "sign verify round trip" {
    const kp = try testKey(0x41);
    const proof = testProof();
    const sig = try sign(proof, kp.secret_key.toBytes());

    try std.testing.expect(verify(proof, sig, kp.public_key.toBytes()));
}

test "tampering any field fails verify" {
    const kp = try testKey(0x42);
    const proof = testProof();
    const sig = try sign(proof, kp.secret_key.toBytes());

    var changed_actor = proof;
    changed_actor.actor = "mod:ren";
    try std.testing.expect(!verify(changed_actor, sig, kp.public_key.toBytes()));

    var changed_target = proof;
    changed_target.target = "member:mei";
    try std.testing.expect(!verify(changed_target, sig, kp.public_key.toBytes()));

    var changed_action = proof;
    changed_action.action ^= 0x01;
    try std.testing.expect(!verify(changed_action, sig, kp.public_key.toBytes()));

    var changed_reason = proof;
    changed_reason.reason_hash[0] ^= 0x80;
    try std.testing.expect(!verify(changed_reason, sig, kp.public_key.toBytes()));

    var changed_policy = proof;
    changed_policy.policy_version += 1;
    try std.testing.expect(!verify(changed_policy, sig, kp.public_key.toBytes()));

    var changed_issued = proof;
    changed_issued.issued_ms += 1;
    try std.testing.expect(!verify(changed_issued, sig, kp.public_key.toBytes()));

    var changed_expiry = proof;
    changed_expiry.expiry_ms += 1;
    try std.testing.expect(!verify(changed_expiry, sig, kp.public_key.toBytes()));
}

test "expiry uses expiry instant" {
    const proof = testProof();

    try std.testing.expect(!expired(proof, proof.expiry_ms - 1));
    try std.testing.expect(expired(proof, proof.expiry_ms));
    try std.testing.expect(expired(proof, proof.expiry_ms + 1));
}

test "reasonHash stable" {
    const a = reasonHash("same reason text");
    const b = reasonHash("same reason text");
    const c = reasonHash("different reason text");

    try std.testing.expectEqualSlices(u8, &a, &b);
    try std.testing.expect(!std.mem.eql(u8, &a, &c));
}

test "canonical bytes can be backed by an unmanaged buffer" {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    const proof = testProof();
    const bytes = try canonicalBytesList(proof, std.testing.allocator, &buf);

    try std.testing.expectEqual(try canonicalLength(proof), bytes.len);
    try std.testing.expect(std.mem.startsWith(u8, bytes, magic));
}
