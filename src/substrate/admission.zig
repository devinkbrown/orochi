// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Object-capability admission grants for the Orochi mesh.
//!
//! This module is intentionally self-contained. A grant body is encoded with a
//! fixed-order canonical binary format and signed with Ed25519. Delegation is a
//! chain of signed grants where each issuer is the previous subject and each
//! step may only reduce the granted capability bitset.

const std = @import("std");

const Ed25519 = std.crypto.sign.Ed25519;

/// Raw Ed25519 public key bytes.
pub const PublicKeyBytes = [Ed25519.PublicKey.encoded_length]u8;

/// Raw Ed25519 signature bytes.
pub const SignatureBytes = [Ed25519.Signature.encoded_length]u8;

/// Stable grant identifier used by revocation sets.
pub const GrantId = [32]u8;

/// Capability bitset. Callers define the meaning of individual bits.
pub const Caps = u64;

/// Maximum scope size accepted by the stack-backed canonical encoder.
pub const max_scope_len = 1024;

const magic = "OROCHI-ADMISSION-GRANT-v1";
const fixed_encoded_len = magic.len + public_key_len * 2 + 4 + @sizeOf(Caps) + @sizeOf(u64) * 2 + grant_id_len;
const public_key_len = Ed25519.PublicKey.encoded_length;
const signature_len = Ed25519.Signature.encoded_length;
const grant_id_len = 32;
const max_canonical_len = fixed_encoded_len + max_scope_len;

/// Unsigned grant statement covered by the Ed25519 signature.
pub const Grant = struct {
    issuer_pubkey: PublicKeyBytes,
    subject_pubkey: PublicKeyBytes,
    scope: []const u8,
    caps: Caps,
    not_before_ms: u64,
    not_after_ms: u64,
    grant_id: GrantId,
};

/// A signed grant suitable for chain verification and authorization.
pub const SignedGrant = struct {
    grant: Grant,
    signature: SignatureBytes,
};

/// Errors produced while building or signing a grant.
pub const SignError = error{
    InvalidTimeWindow,
    IssuerKeyMismatch,
    ScopeTooLarge,
    IdentityElement,
    KeyMismatch,
    NonCanonical,
    WeakPublicKey,
};

/// Errors produced while verifying a single grant signature.
pub const VerifyGrantError = error{
    InvalidTimeWindow,
    ScopeTooLarge,
    BadSignature,
};

/// Errors produced while checking delegation-chain authority.
pub const ChainError = VerifyGrantError || error{
    EmptyChain,
    WrongRoot,
    BrokenChainLink,
    NotYetValid,
    Expired,
    CapabilityWidened,
};

/// A managed set of revoked grant identifiers.
pub const RevocationSet = struct {
    map: std.AutoHashMap(GrantId, void),

    /// Create an empty revocation set.
    pub fn init(allocator: std.mem.Allocator) RevocationSet {
        return .{ .map = std.AutoHashMap(GrantId, void).init(allocator) };
    }

    /// Release hash-map storage.
    pub fn deinit(self: *RevocationSet) void {
        self.map.deinit();
    }

    /// Mark `grant_id` as revoked.
    pub fn revoke(self: *RevocationSet, grant_id: GrantId) !void {
        try self.map.put(grant_id, {});
    }

    /// Return true when `grant_id` has been revoked.
    pub fn contains(self: *const RevocationSet, grant_id: GrantId) bool {
        return self.map.contains(grant_id);
    }
};

/// Return a one-bit capability mask for `index`.
pub fn capBit(index: u6) Caps {
    return @as(Caps, 1) << index;
}

/// Return true when `actual` contains every bit in `needed`.
pub fn hasCaps(actual: Caps, needed: Caps) bool {
    return (actual & needed) == needed;
}

/// Encode `grant` into the canonical byte representation covered by signatures.
pub fn encodeCanonical(out: []u8, grant: Grant) VerifyGrantError!usize {
    try validateGrantShape(grant);

    const needed = canonicalLength(grant);
    if (out.len < needed) return error.ScopeTooLarge;

    var pos: usize = 0;
    copyBytes(out, &pos, magic);
    copyBytes(out, &pos, &grant.issuer_pubkey);
    copyBytes(out, &pos, &grant.subject_pubkey);
    writeU32(out, &pos, @intCast(grant.scope.len));
    copyBytes(out, &pos, grant.scope);
    writeU64(out, &pos, grant.caps);
    writeU64(out, &pos, grant.not_before_ms);
    writeU64(out, &pos, grant.not_after_ms);
    copyBytes(out, &pos, &grant.grant_id);
    return pos;
}

/// Sign a grant body with its issuer key pair.
pub fn sign(grant: Grant, issuer_keypair: Ed25519.KeyPair) SignError!SignatureBytes {
    if (!std.mem.eql(u8, &grant.issuer_pubkey, &issuer_keypair.public_key.toBytes())) {
        return error.IssuerKeyMismatch;
    }

    var buf: [max_canonical_len]u8 = undefined;
    const len = encodeCanonical(&buf, grant) catch |err| switch (err) {
        error.InvalidTimeWindow => return error.InvalidTimeWindow,
        error.ScopeTooLarge => return error.ScopeTooLarge,
        error.BadSignature => unreachable,
    };
    const sig = try issuer_keypair.sign(buf[0..len], null);
    return sig.toBytes();
}

/// Verify that `signature` was produced by `grant.issuer_pubkey` over `grant`.
pub fn verifyGrant(grant: Grant, signature: SignatureBytes) VerifyGrantError!void {
    var buf: [max_canonical_len]u8 = undefined;
    const len = try encodeCanonical(&buf, grant);
    const pk = Ed25519.PublicKey.fromBytes(grant.issuer_pubkey) catch return error.BadSignature;
    const sig = Ed25519.Signature.fromBytes(signature);
    sig.verifyStrict(buf[0..len], pk) catch return error.BadSignature;
}

/// Verify signatures, issuer linkage, validity windows, and narrowing caps.
pub fn verifyChain(root_pubkey: PublicKeyBytes, chain: []const SignedGrant, now_ms: u64) ChainError!void {
    if (chain.len == 0) return error.EmptyChain;
    if (!std.mem.eql(u8, &chain[0].grant.issuer_pubkey, &root_pubkey)) {
        return error.WrongRoot;
    }

    var previous_caps: Caps = 0;
    for (chain, 0..) |signed, i| {
        try verifyGrant(signed.grant, signed.signature);
        try verifyTime(signed.grant, now_ms);

        if (i > 0) {
            const previous_subject = chain[i - 1].grant.subject_pubkey;
            if (!std.mem.eql(u8, &signed.grant.issuer_pubkey, &previous_subject)) {
                return error.BrokenChainLink;
            }
            if ((signed.grant.caps & ~previous_caps) != 0) {
                return error.CapabilityWidened;
            }
        }

        previous_caps = signed.grant.caps;
    }
}

/// Return an authorization decision for a signed delegation chain.
///
/// This validates grant signatures, chain linkage, validity windows, revocation
/// state, exact scope match, final subject, and the requested capability bits.
pub fn authorize(
    chain: []const SignedGrant,
    trusted_root: PublicKeyBytes,
    subject: PublicKeyBytes,
    scope: []const u8,
    needed_caps: Caps,
    now_ms: u64,
    revocations: *const RevocationSet,
) bool {
    if (chain.len == 0) return false;
    verifyChain(trusted_root, chain, now_ms) catch return false;

    var effective_caps: Caps = ~@as(Caps, 0);
    for (chain) |signed| {
        if (revocations.contains(signed.grant.grant_id)) return false;
        if (!std.mem.eql(u8, signed.grant.scope, scope)) return false;
        effective_caps &= signed.grant.caps;
    }

    const terminal = chain[chain.len - 1].grant;
    if (!std.mem.eql(u8, &terminal.subject_pubkey, &subject)) return false;
    return hasCaps(effective_caps, needed_caps);
}

fn canonicalLength(grant: Grant) usize {
    return fixed_encoded_len + grant.scope.len;
}

fn validateGrantShape(grant: Grant) VerifyGrantError!void {
    if (grant.scope.len > max_scope_len) return error.ScopeTooLarge;
    if (grant.not_after_ms < grant.not_before_ms) return error.InvalidTimeWindow;
}

fn verifyTime(grant: Grant, now_ms: u64) ChainError!void {
    if (now_ms < grant.not_before_ms) return error.NotYetValid;
    if (now_ms > grant.not_after_ms) return error.Expired;
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

fn testSeed(byte: u8) [Ed25519.KeyPair.seed_length]u8 {
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    @memset(&seed, byte);
    return seed;
}

fn testGrantId(byte: u8) GrantId {
    var id: GrantId = undefined;
    @memset(&id, byte);
    return id;
}

fn testKey(byte: u8) !Ed25519.KeyPair {
    return try Ed25519.KeyPair.generateDeterministic(testSeed(byte));
}

fn makeGrant(
    issuer: Ed25519.KeyPair,
    subject: Ed25519.KeyPair,
    scope: []const u8,
    caps: Caps,
    id_byte: u8,
) Grant {
    return .{
        .issuer_pubkey = issuer.public_key.toBytes(),
        .subject_pubkey = subject.public_key.toBytes(),
        .scope = scope,
        .caps = caps,
        .not_before_ms = 1_000,
        .not_after_ms = 2_000,
        .grant_id = testGrantId(id_byte),
    };
}

fn issueGrant(grant: Grant, issuer: Ed25519.KeyPair) !SignedGrant {
    return .{
        .grant = grant,
        .signature = try sign(grant, issuer),
    };
}

test "issue verify authorize accept" {
    const allocator = std.testing.allocator;
    var revocations = RevocationSet.init(allocator);
    defer revocations.deinit();

    const issuer = try testKey(1);
    const subject = try testKey(2);
    const read = capBit(0);
    const grant = makeGrant(issuer, subject, "#orochi", read, 9);
    const signed = try issueGrant(grant, issuer);

    try verifyGrant(signed.grant, signed.signature);
    try verifyChain(issuer.public_key.toBytes(), &.{signed}, 1_500);
    try std.testing.expect(authorize(&.{signed}, issuer.public_key.toBytes(), subject.public_key.toBytes(), "#orochi", read, 1_500, &revocations));
}

test "expired grant is rejected" {
    const allocator = std.testing.allocator;
    var revocations = RevocationSet.init(allocator);
    defer revocations.deinit();

    const issuer = try testKey(3);
    const subject = try testKey(4);
    const signed = try issueGrant(makeGrant(issuer, subject, "#ops", capBit(0), 10), issuer);

    try std.testing.expectError(error.Expired, verifyChain(issuer.public_key.toBytes(), &.{signed}, 2_001));
    try std.testing.expect(!authorize(&.{signed}, issuer.public_key.toBytes(), subject.public_key.toBytes(), "#ops", capBit(0), 2_001, &revocations));
}

test "wrong scope is rejected" {
    const allocator = std.testing.allocator;
    var revocations = RevocationSet.init(allocator);
    defer revocations.deinit();

    const issuer = try testKey(5);
    const subject = try testKey(6);
    const signed = try issueGrant(makeGrant(issuer, subject, "#ops", capBit(0), 11), issuer);

    try std.testing.expect(!authorize(&.{signed}, issuer.public_key.toBytes(), subject.public_key.toBytes(), "#dev", capBit(0), 1_500, &revocations));
}

test "missing capability is rejected" {
    const allocator = std.testing.allocator;
    var revocations = RevocationSet.init(allocator);
    defer revocations.deinit();

    const issuer = try testKey(7);
    const subject = try testKey(8);
    const read = capBit(0);
    const write = capBit(1);
    const signed = try issueGrant(makeGrant(issuer, subject, "#ops", read, 12), issuer);

    try std.testing.expect(!authorize(&.{signed}, issuer.public_key.toBytes(), subject.public_key.toBytes(), "#ops", write, 1_500, &revocations));
}

test "revoked grant id is rejected" {
    const allocator = std.testing.allocator;
    var revocations = RevocationSet.init(allocator);
    defer revocations.deinit();

    const issuer = try testKey(9);
    const subject = try testKey(10);
    const signed = try issueGrant(makeGrant(issuer, subject, "#ops", capBit(0), 13), issuer);
    try revocations.revoke(signed.grant.grant_id);

    try std.testing.expect(!authorize(&.{signed}, issuer.public_key.toBytes(), subject.public_key.toBytes(), "#ops", capBit(0), 1_500, &revocations));
}

test "tampered body or signature is rejected" {
    const issuer = try testKey(11);
    const subject = try testKey(12);
    const other = try testKey(13);
    const signed = try issueGrant(makeGrant(issuer, subject, "#ops", capBit(0), 14), issuer);

    var tampered_body = signed.grant;
    tampered_body.subject_pubkey = other.public_key.toBytes();
    try std.testing.expectError(error.BadSignature, verifyGrant(tampered_body, signed.signature));

    var tampered_sig = signed.signature;
    tampered_sig[0] ^= 0x80;
    try std.testing.expectError(error.BadSignature, verifyGrant(signed.grant, tampered_sig));
}

test "three node delegation chain authorizes final subject" {
    const allocator = std.testing.allocator;
    var revocations = RevocationSet.init(allocator);
    defer revocations.deinit();

    const a = try testKey(20);
    const b = try testKey(21);
    const c = try testKey(22);
    const read = capBit(0);
    const write = capBit(1);
    const ab = try issueGrant(makeGrant(a, b, "#mesh", read | write, 20), a);
    const bc = try issueGrant(makeGrant(b, c, "#mesh", read, 21), b);
    const chain = [_]SignedGrant{ ab, bc };

    try verifyChain(a.public_key.toBytes(), &chain, 1_500);
    try std.testing.expect(authorize(&chain, a.public_key.toBytes(), c.public_key.toBytes(), "#mesh", read, 1_500, &revocations));
    try std.testing.expect(!authorize(&chain, a.public_key.toBytes(), c.public_key.toBytes(), "#mesh", write, 1_500, &revocations));
}

test "delegation that widens capabilities is rejected" {
    const a = try testKey(30);
    const b = try testKey(31);
    const c = try testKey(32);
    const read = capBit(0);
    const write = capBit(1);
    const ab = try issueGrant(makeGrant(a, b, "#mesh", read, 30), a);
    const bc = try issueGrant(makeGrant(b, c, "#mesh", read | write, 31), b);
    const chain = [_]SignedGrant{ ab, bc };

    try std.testing.expectError(error.CapabilityWidened, verifyChain(a.public_key.toBytes(), &chain, 1_500));
}

test "broken chain link is rejected" {
    const a = try testKey(40);
    const b = try testKey(41);
    const c = try testKey(42);
    const d = try testKey(43);
    const ab = try issueGrant(makeGrant(a, b, "#mesh", capBit(0), 40), a);
    const cd = try issueGrant(makeGrant(c, d, "#mesh", capBit(0), 41), c);
    const chain = [_]SignedGrant{ ab, cd };

    try std.testing.expectError(error.BrokenChainLink, verifyChain(a.public_key.toBytes(), &chain, 1_500));
}
