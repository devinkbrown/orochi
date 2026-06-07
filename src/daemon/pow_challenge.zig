//! Privacy-friendly proof-of-work challenge helpers for connection admission.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const nonce_len: usize = 16;
pub const solution_len: usize = 8;
pub const default_ttl_ms: i64 = 120_000;

pub const Challenge = struct {
    nonce: [nonce_len]u8,
    difficulty: u6,
    issued_ms: i64,
    ttl_ms: i64,

    pub fn expired(self: Challenge, now_ms: i64) bool {
        if (self.ttl_ms <= 0) return true;
        if (now_ms < self.issued_ms) return false;
        return now_ms - self.issued_ms >= self.ttl_ms;
    }
};

pub fn issue(rng: std.Random, difficulty: u6, now_ms: i64) Challenge {
    var challenge = Challenge{
        .nonce = undefined,
        .difficulty = difficulty,
        .issued_ms = now_ms,
        .ttl_ms = default_ttl_ms,
    };
    rng.bytes(&challenge.nonce);
    return challenge;
}

pub fn verify(challenge: Challenge, solution: u64, now_ms: i64) bool {
    if (challenge.expired(now_ms)) return false;

    var digest: [Sha256.digest_length]u8 = undefined;
    digestChallenge(challenge.nonce, solution, &digest);
    return hasLeadingZeroBits(digest, challenge.difficulty);
}

pub fn solve(challenge: Challenge, max_iters: u64) ?u64 {
    var solution: u64 = 0;
    while (solution < max_iters) : (solution += 1) {
        var digest: [Sha256.digest_length]u8 = undefined;
        digestChallenge(challenge.nonce, solution, &digest);
        if (hasLeadingZeroBits(digest, challenge.difficulty)) return solution;
    }
    return null;
}

fn digestChallenge(nonce: [nonce_len]u8, solution: u64, out: *[Sha256.digest_length]u8) void {
    var solution_bytes: [solution_len]u8 = undefined;
    std.mem.writeInt(u64, &solution_bytes, solution, .little);

    var hasher = Sha256.init(.{});
    hasher.update(&nonce);
    hasher.update(&solution_bytes);
    hasher.final(out);
}

fn hasLeadingZeroBits(digest: [Sha256.digest_length]u8, bits: u6) bool {
    const bit_count: usize = bits;
    const full_zero_bytes = bit_count / 8;
    const partial_bits = bit_count % 8;

    var byte_index: usize = 0;
    while (byte_index < full_zero_bytes) : (byte_index += 1) {
        if (digest[byte_index] != 0) return false;
    }

    if (partial_bits == 0) return true;

    const shift: u3 = @intCast(8 - partial_bits);
    const mask: u8 = @as(u8, 0xff) << shift;
    return digest[full_zero_bytes] & mask == 0;
}

test "solve result verifies before expiry" {
    var prng = std.Random.DefaultPrng.init(0x6d697a75636869);
    const challenge = issue(prng.random(), 8, 1_000);
    const solution = solve(challenge, 10_000) orelse return error.NoSolution;

    try std.testing.expect(verify(challenge, solution, 1_500));
}

test "wrong solution fails" {
    var prng = std.Random.DefaultPrng.init(0x77726f6e67);
    const challenge = issue(prng.random(), 10, 2_000);
    const solution = solve(challenge, 50_000) orelse return error.NoSolution;

    try std.testing.expect(!verify(challenge, solution +% 1, 2_100));
}

test "expired challenge fails even with valid work" {
    var prng = std.Random.DefaultPrng.init(0x65787069726564);
    var challenge = issue(prng.random(), 8, 3_000);
    challenge.ttl_ms = 500;
    const solution = solve(challenge, 10_000) orelse return error.NoSolution;

    try std.testing.expect(!verify(challenge, solution, 3_500));
}

test "difficulty zero accepts the first candidate" {
    var prng = std.Random.DefaultPrng.init(0x7a65726f);
    const challenge = issue(prng.random(), 0, 4_000);

    try std.testing.expectEqual(@as(?u64, 0), solve(challenge, 1));
    try std.testing.expect(verify(challenge, 0, 4_001));
}

test "leading zero bit predicate respects bit precision" {
    const seven_bits = [_]u8{0x01} ++ [_]u8{0x00} ** (Sha256.digest_length - 1);
    const eight_bits = [_]u8{0x00, 0x7f} ++ [_]u8{0x00} ** (Sha256.digest_length - 2);
    const not_nine_bits = [_]u8{0x00, 0x80} ++ [_]u8{0x00} ** (Sha256.digest_length - 2);

    try std.testing.expect(hasLeadingZeroBits(seven_bits, 7));
    try std.testing.expect(!hasLeadingZeroBits(seven_bits, 8));
    try std.testing.expect(hasLeadingZeroBits(eight_bits, 9));
    try std.testing.expect(!hasLeadingZeroBits(not_nine_bits, 9));
}
