// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Signed dotted delta envelopes for Goryu-Sync CRDT mutations.
//!
//! The relay is not part of the trust boundary: peers verify that the origin
//! node's Ed25519 key signed the canonical envelope CID, then separately ask a
//! caller-supplied capability predicate whether that origin may apply the
//! family/scope/HLC mutation.
const std = @import("std");

const Blake3 = std.crypto.hash.Blake3;
const StdEd25519 = std.crypto.sign.Ed25519;

pub const NodeId = [20]u8;
pub const Cid = [Blake3.digest_length]u8;
pub const public_key_len = StdEd25519.PublicKey.encoded_length;
pub const signature_len = StdEd25519.Signature.encoded_length;
pub const seed_len = StdEd25519.KeyPair.seed_length;
pub const PublicKey = [public_key_len]u8;
pub const Signature = [signature_len]u8;
pub const KeyPair = StdEd25519.KeyPair;
pub const Seed = [seed_len]u8;

const canonical_magic = "MZ-SIGNED-DELTA-v1";

pub const EncodeError = error{OutputTooSmall};
pub const SignError = std.crypto.errors.IdentityElementError ||
    std.crypto.errors.KeyMismatchError ||
    std.crypto.errors.NonCanonicalError ||
    std.crypto.errors.WeakPublicKeyError ||
    error{OriginNodeMismatch};

pub const Envelope = struct {
    origin_node: NodeId,
    hlc: u64,
    family: u8,
    scope: []const u8,
    op_bytes: []const u8,
};

pub const SignedDelta = struct {
    env: Envelope,
    cid: Cid,
    signature: Signature,
};

pub const AuthorizedFor = *const fn (
    origin_node: NodeId,
    family: u8,
    scope: []const u8,
    hlc: u64,
) bool;

/// Derive the 160-bit origin node id from the Ed25519 public key.
pub fn nodeIdFromPublicKey(origin_pubkey: PublicKey) NodeId {
    var digest: Cid = undefined;
    Blake3.hash(&origin_pubkey, &digest, .{});

    var out: NodeId = undefined;
    @memcpy(&out, digest[0..out.len]);
    return out;
}

/// Canonical unsigned envelope size.
pub fn encodedLen(env: Envelope) usize {
    return canonical_magic.len +
        env.origin_node.len +
        @sizeOf(u64) +
        @sizeOf(u8) +
        @sizeOf(u64) +
        env.scope.len +
        @sizeOf(u64) +
        env.op_bytes.len;
}

/// Encode the unsigned envelope in canonical fixed-order bytes:
/// magic || origin_node || hlc_be || family || scope_len_be || scope ||
/// op_len_be || op_bytes.
pub fn encode(env: Envelope, out: []u8) EncodeError![]const u8 {
    const need = encodedLen(env);
    if (out.len < need) return error.OutputTooSmall;

    var cursor: usize = 0;
    append(out, &cursor, canonical_magic);
    append(out, &cursor, &env.origin_node);
    writeU64(out, &cursor, env.hlc);
    out[cursor] = env.family;
    cursor += 1;
    writeU64(out, &cursor, @intCast(env.scope.len));
    append(out, &cursor, env.scope);
    writeU64(out, &cursor, @intCast(env.op_bytes.len));
    append(out, &cursor, env.op_bytes);

    return out[0..cursor];
}

pub const DecodeError = error{ Truncated, BadMagic, TrailingBytes, LengthOverflow };

/// Decode a canonical unsigned envelope. Zero-copy: `scope` and `op_bytes` in
/// the returned envelope borrow `bytes`, so the buffer must outlive the result.
pub fn decode(bytes: []const u8) DecodeError!Envelope {
    var r = Cursor{ .buf = bytes };
    if (!std.mem.eql(u8, try r.take(canonical_magic.len), canonical_magic)) return error.BadMagic;
    const origin = try r.take(@sizeOf(NodeId));
    const hlc = try r.takeU64();
    const family = (try r.take(1))[0];
    const scope_len = try r.takeLen();
    const scope = try r.take(scope_len);
    const op_len = try r.takeLen();
    const op_bytes = try r.take(op_len);
    if (!r.done()) return error.TrailingBytes;

    var env = Envelope{ .origin_node = undefined, .hlc = hlc, .family = family, .scope = scope, .op_bytes = op_bytes };
    @memcpy(&env.origin_node, origin);
    return env;
}

/// Wire size of a full signed delta: canonical envelope followed by the
/// detached signature. The CID is recomputed on decode, never transmitted.
pub fn signedWireLen(env: Envelope) usize {
    return encodedLen(env) + signature_len;
}

/// Encode `signed` as `encode(env) || signature`.
pub fn encodeSigned(signed: SignedDelta, out: []u8) EncodeError![]const u8 {
    const total = signedWireLen(signed.env);
    if (out.len < total) return error.OutputTooSmall;
    const env_bytes = try encode(signed.env, out);
    @memcpy(out[env_bytes.len..][0..signature_len], &signed.signature);
    return out[0..total];
}

/// Decode a full signed delta from the wire, recomputing the CID from the
/// envelope so a tampered payload yields a CID the signature cannot match.
/// Zero-copy like `decode`; the result borrows `bytes`. Always pass the result
/// through `verifyOne`/`verifyAuthorized` before trusting it.
pub fn decodeSigned(bytes: []const u8) DecodeError!SignedDelta {
    if (bytes.len < signature_len) return error.Truncated;
    const split = bytes.len - signature_len;
    const env = try decode(bytes[0..split]);
    return .{
        .env = env,
        .cid = cid(env),
        .signature = bytes[split..][0..signature_len].*,
    };
}

const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    fn done(self: *const Cursor) bool {
        return self.pos == self.buf.len;
    }

    fn take(self: *Cursor, n: usize) DecodeError![]const u8 {
        if (n > self.buf.len - self.pos) return error.Truncated;
        defer self.pos += n;
        return self.buf[self.pos..][0..n];
    }

    fn takeU64(self: *Cursor) DecodeError!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .big);
    }

    fn takeLen(self: *Cursor) DecodeError!usize {
        const v = try self.takeU64();
        if (v > std.math.maxInt(usize)) return error.LengthOverflow;
        return @intCast(v);
    }
};

/// Compute BLAKE3(canonical unsigned envelope).
pub fn cid(env: Envelope) Cid {
    var h = Blake3.init(.{});
    hashCanonical(&h, env);

    var out: Cid = undefined;
    h.final(&out);
    return out;
}

/// Sign the canonical CID with the origin key. The envelope origin_node must
/// match BLAKE3-160(origin public key).
pub fn sign(env: Envelope, origin_secret: *const KeyPair) SignError!SignedDelta {
    const origin_pubkey = origin_secret.public_key.toBytes();
    if (!ctEql(&env.origin_node, &nodeIdFromPublicKey(origin_pubkey))) {
        return error.OriginNodeMismatch;
    }

    const content_id = cid(env);
    const signature = try origin_secret.sign(&content_id, null);
    return .{
        .env = env,
        .cid = content_id,
        .signature = signature.toBytes(),
    };
}

/// Verify the origin signature and public-key-to-origin binding.
pub fn verifyOne(signed: SignedDelta, origin_pubkey: PublicKey) bool {
    if (!ctEql(&signed.env.origin_node, &nodeIdFromPublicKey(origin_pubkey))) {
        return false;
    }

    const expected_cid = cid(signed.env);
    if (!ctEql(&expected_cid, &signed.cid)) return false;

    const public_key = StdEd25519.PublicKey.fromBytes(origin_pubkey) catch return false;
    const signature = StdEd25519.Signature.fromBytes(signed.signature);
    signature.verify(&expected_cid, public_key) catch return false;
    return true;
}

/// Runtime batch verification. `sign.zig` does not currently expose a batch
/// verifier, so this preserves the same all-or-nothing API with a per-item
/// verification loop.
pub fn verifyBatch(signeds: []const SignedDelta, pubkeys: []const PublicKey) bool {
    if (signeds.len != pubkeys.len) return false;
    for (signeds, pubkeys) |signed, pubkey| {
        if (!verifyOne(signed, pubkey)) return false;
    }
    return true;
}

/// Verify the signature and then gate application through caller authority.
pub fn verifyAuthorized(
    signed: SignedDelta,
    origin_pubkey: PublicKey,
    authorizedFor: AuthorizedFor,
) bool {
    if (!verifyOne(signed, origin_pubkey)) return false;
    return authorizedFor(
        signed.env.origin_node,
        signed.env.family,
        signed.env.scope,
        signed.env.hlc,
    );
}

fn hashCanonical(h: *Blake3, env: Envelope) void {
    var len_buf: [8]u8 = undefined;

    h.update(canonical_magic);
    h.update(&env.origin_node);
    std.mem.writeInt(u64, &len_buf, env.hlc, .big);
    h.update(&len_buf);
    h.update(&[_]u8{env.family});
    std.mem.writeInt(u64, &len_buf, @intCast(env.scope.len), .big);
    h.update(&len_buf);
    h.update(env.scope);
    std.mem.writeInt(u64, &len_buf, @intCast(env.op_bytes.len), .big);
    h.update(&len_buf);
    h.update(env.op_bytes);
}

fn append(out: []u8, cursor: *usize, bytes: []const u8) void {
    @memcpy(out[cursor.*..][0..bytes.len], bytes);
    cursor.* += bytes.len;
}

fn writeU64(out: []u8, cursor: *usize, value: u64) void {
    std.mem.writeInt(u64, out[cursor.*..][0..8], value, .big);
    cursor.* += 8;
}

fn ctEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

fn testKey(seed_byte: u8) !KeyPair {
    return KeyPair.generateDeterministic(@as([seed_len]u8, @splat(seed_byte)));
}

fn testEnvelope(kp: *const KeyPair, hlc: u64, scope: []const u8, op: []const u8) Envelope {
    const public_key = kp.public_key.toBytes();
    return .{
        .origin_node = nodeIdFromPublicKey(public_key),
        .hlc = hlc,
        .family = 7,
        .scope = scope,
        .op_bytes = op,
    };
}

test "sign and verify round-trip" {
    const kp = try testKey(0x42);
    const public_key = kp.public_key.toBytes();

    const env = testEnvelope(&kp, 1234, "#goryu", "join:42:+o");
    const signed = try sign(env, &kp);

    try std.testing.expectEqual(cid(env), signed.cid);
    try std.testing.expect(verifyOne(signed, public_key));
}

test "tampered op hlc and scope fail verification" {
    const kp = try testKey(0x43);
    const public_key = kp.public_key.toBytes();

    const signed = try sign(testEnvelope(&kp, 9, "#chan", "mode:+i"), &kp);

    var tampered_op = signed;
    tampered_op.env.op_bytes = "mode:-i";
    try std.testing.expect(!verifyOne(tampered_op, public_key));

    var tampered_hlc = signed;
    tampered_hlc.env.hlc += 1;
    try std.testing.expect(!verifyOne(tampered_hlc, public_key));

    var tampered_scope = signed;
    tampered_scope.env.scope = "#other";
    try std.testing.expect(!verifyOne(tampered_scope, public_key));
}

test "cid is stable and canonical" {
    const env = Envelope{
        .origin_node = [_]u8{
            0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
            10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        },
        .hlc = 0x0102030405060708,
        .family = 0x2a,
        .scope = "chan",
        .op_bytes = "op",
    };

    var a: [128]u8 = undefined;
    var b: [128]u8 = undefined;
    const enc_a = try encode(env, &a);
    const enc_b = try encode(env, &b);
    const heap = try std.testing.allocator.alloc(u8, encodedLen(env));
    defer std.testing.allocator.free(heap);
    const enc_heap = try encode(env, heap);

    try std.testing.expectEqualSlices(u8, enc_a, enc_b);
    try std.testing.expectEqualSlices(u8, enc_a, enc_heap);
    try std.testing.expectEqual(cid(env), cid(env));
    try std.testing.expectEqual(@as(usize, encodedLen(env)), enc_a.len);
    try std.testing.expectEqualSlices(u8, canonical_magic, enc_a[0..canonical_magic.len]);
    try std.testing.expectEqualSlices(u8, &env.origin_node, enc_a[canonical_magic.len..][0..20]);
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), std.mem.readInt(
        u64,
        enc_a[canonical_magic.len + 20 ..][0..8],
        .big,
    ));
    try std.testing.expectEqual(@as(u8, 0x2a), enc_a[canonical_magic.len + 28]);
    try std.testing.expectEqual(@as(u64, 4), std.mem.readInt(
        u64,
        enc_a[canonical_magic.len + 29 ..][0..8],
        .big,
    ));
    try std.testing.expectEqualSlices(u8, "chan", enc_a[canonical_magic.len + 37 ..][0..4]);
    try std.testing.expectEqual(@as(u64, 2), std.mem.readInt(
        u64,
        enc_a[canonical_magic.len + 41 ..][0..8],
        .big,
    ));
    try std.testing.expectEqualSlices(u8, "op", enc_a[canonical_magic.len + 49 ..][0..2]);
}

test "batch verify accepts all valid and rejects any invalid" {
    const kp1 = try testKey(0x44);
    const kp2 = try testKey(0x45);

    var signed = [_]SignedDelta{
        try sign(testEnvelope(&kp1, 1, "#a", "one"), &kp1),
        try sign(testEnvelope(&kp2, 2, "#b", "two"), &kp2),
    };
    const pubkeys = [_]PublicKey{ kp1.public_key.toBytes(), kp2.public_key.toBytes() };

    try std.testing.expect(verifyBatch(signed[0..], pubkeys[0..]));

    signed[1].signature[0] ^= 0x01;
    try std.testing.expect(!verifyBatch(signed[0..], pubkeys[0..]));
}

test "authorizedFor predicate gates apply" {
    const Pred = struct {
        fn allow(origin_node: NodeId, family: u8, scope: []const u8, hlc: u64) bool {
            _ = origin_node;
            return family == 7 and hlc >= 10 and std.mem.eql(u8, scope, "#allowed");
        }

        fn deny(origin_node: NodeId, family: u8, scope: []const u8, hlc: u64) bool {
            _ = origin_node;
            _ = family;
            _ = scope;
            _ = hlc;
            return false;
        }
    };

    const kp = try testKey(0x46);
    const public_key = kp.public_key.toBytes();

    const signed = try sign(testEnvelope(&kp, 10, "#allowed", "delta"), &kp);
    try std.testing.expect(verifyAuthorized(signed, public_key, Pred.allow));
    try std.testing.expect(!verifyAuthorized(signed, public_key, Pred.deny));

    var wrong_scope = signed;
    wrong_scope.env.scope = "#denied";
    try std.testing.expect(!verifyAuthorized(wrong_scope, public_key, Pred.allow));
}

test "wire round-trip preserves a verifiable signed delta" {
    const kp = try testKey(0x61);
    const public_key = kp.public_key.toBytes();
    const signed = try sign(testEnvelope(&kp, 7777, "#wire", "join:99:+v"), &kp);

    var buf: [256]u8 = undefined;
    const wire = try encodeSigned(signed, &buf);
    try std.testing.expectEqual(signedWireLen(signed.env), wire.len);

    const back = try decodeSigned(wire);
    try std.testing.expect(verifyOne(back, public_key));
    try std.testing.expectEqual(signed.env.hlc, back.env.hlc);
    try std.testing.expectEqual(signed.env.family, back.env.family);
    try std.testing.expectEqualSlices(u8, signed.env.scope, back.env.scope);
    try std.testing.expectEqualSlices(u8, signed.env.op_bytes, back.env.op_bytes);
    try std.testing.expectEqual(signed.cid, back.cid);
}

test "wire decode reverification rejects tampering and forgery" {
    const kp = try testKey(0x62);
    const public_key = kp.public_key.toBytes();
    const signed = try sign(testEnvelope(&kp, 42, "#wire", "mode:+i"), &kp);

    var buf: [256]u8 = undefined;
    const wire = try encodeSigned(signed, &buf);

    // A genuine copy verifies.
    try std.testing.expect(verifyOne(try decodeSigned(wire), public_key));

    // Flip a payload byte (last op byte, just before the detached signature):
    // the recomputed CID no longer matches the signature.
    var tampered_op = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(tampered_op);
    tampered_op[tampered_op.len - signature_len - 1] ^= 0x01;
    try std.testing.expect(!verifyOne(try decodeSigned(tampered_op), public_key));

    // Flip a signature byte.
    var tampered_sig = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(tampered_sig);
    tampered_sig[tampered_sig.len - 1] ^= 0x01;
    try std.testing.expect(!verifyOne(try decodeSigned(tampered_sig), public_key));

    // A different key's view of the same bytes fails the pubkey->origin binding.
    const other = try testKey(0x99);
    try std.testing.expect(!verifyOne(try decodeSigned(wire), other.public_key.toBytes()));
}

test "wire decode rejects malformed buffers" {
    const kp = try testKey(0x63);
    const signed = try sign(testEnvelope(&kp, 1, "#x", "y"), &kp);
    var buf: [256]u8 = undefined;
    const wire = try encodeSigned(signed, &buf);

    try std.testing.expectError(error.Truncated, decodeSigned(wire[0 .. signature_len - 1]));
    try std.testing.expectError(error.Truncated, decodeSigned(wire[0 .. wire.len - 1]));

    var bad_magic = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(bad_magic);
    bad_magic[0] ^= 0xff;
    try std.testing.expectError(error.BadMagic, decodeSigned(bad_magic));

    var trailing: [300]u8 = undefined;
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0; // one extra byte inside the envelope region
    try std.testing.expectError(error.TrailingBytes, decodeSigned(trailing[0 .. wire.len + 1]));
}

test "encodeSigned reports an undersized buffer" {
    const kp = try testKey(0x64);
    const signed = try sign(testEnvelope(&kp, 1, "#x", "yy"), &kp);
    var small: [8]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, encodeSigned(signed, &small));
}

test {
    std.testing.refAllDecls(@This());
}
