//! Canonically-signed structured objects.
//!
//! Composes the CoilPack canonical value layer (`coilpack_value`) with Ed25519
//! so capability grants, config blobs, and metadata get a SIGNATURE-STABLE
//! representation: two objects with the same logical contents (regardless of map
//! key insertion order) encode to identical bytes and therefore produce
//! identical signatures and verify interchangeably. The signature covers the
//! canonical bytes, so a relay/cache cannot reorder fields to break or forge it.
const std = @import("std");

const cpv = @import("coilpack_value.zig");

const Ed25519 = std.crypto.sign.Ed25519;

pub const Value = cpv.Value;
pub const MapEntry = cpv.MapEntry;
pub const KeyPair = Ed25519.KeyPair;
pub const PublicKey = [Ed25519.PublicKey.encoded_length]u8;
pub const Signature = [Ed25519.Signature.encoded_length]u8;

pub const SignedObject = struct {
    /// Canonical CoilPack encoding of the object (owned).
    canonical: []u8,
    signature: Signature,
    signer: PublicKey,

    pub fn deinit(self: *SignedObject, allocator: std.mem.Allocator) void {
        allocator.free(self.canonical);
        self.* = undefined;
    }
};

/// Canonically encode `value` and sign the bytes with `kp`.
pub fn sign(allocator: std.mem.Allocator, value: Value, kp: KeyPair) !SignedObject {
    const canonical = try cpv.Encoder.encode(allocator, value);
    errdefer allocator.free(canonical);
    const sig = try kp.sign(canonical, null);
    return .{
        .canonical = canonical,
        .signature = sig.toBytes(),
        .signer = kp.public_key.toBytes(),
    };
}

/// Verify the signature over the canonical bytes by the embedded signer key.
/// Pass `expected_signer` to additionally pin who must have signed it.
pub fn verify(obj: SignedObject, expected_signer: ?PublicKey) bool {
    if (expected_signer) |want| {
        if (!std.crypto.timing_safe.eql(PublicKey, obj.signer, want)) return false;
    }
    const pk = Ed25519.PublicKey.fromBytes(obj.signer) catch return false;
    const sig = Ed25519.Signature.fromBytes(obj.signature);
    sig.verify(obj.canonical, pk) catch return false;
    return true;
}

/// Decode the object's canonical bytes back into a Value (owned by the caller).
pub fn decodeValue(allocator: std.mem.Allocator, obj: SignedObject) !Value {
    return cpv.Decoder.decode(allocator, obj.canonical);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn key(seed: u8) !KeyPair {
    return KeyPair.generateDeterministic([_]u8{seed} ** Ed25519.KeyPair.seed_length);
}

test "sign/verify round-trip and signer pinning" {
    const allocator = testing.allocator;
    const kp = try key(0x01);
    var entries = [_]MapEntry{
        .{ .key = "scope", .value = .{ .string = "#root" } },
        .{ .key = "caps", .value = .{ .unsigned = 7 } },
    };
    var obj = try sign(allocator, .{ .map = &entries }, kp);
    defer obj.deinit(allocator);

    try testing.expect(verify(obj, null));
    try testing.expect(verify(obj, kp.public_key.toBytes()));
    const wrong = (try key(0x02)).public_key.toBytes();
    try testing.expect(!verify(obj, wrong)); // signer pin rejects a different key
}

test "signature is stable across map key ordering" {
    const allocator = testing.allocator;
    const kp = try key(0x03);

    var a_entries = [_]MapEntry{
        .{ .key = "alpha", .value = .{ .unsigned = 1 } },
        .{ .key = "beta", .value = .{ .string = "x" } },
        .{ .key = "gamma", .value = .{ .boolean = true } },
    };
    var b_entries = [_]MapEntry{ // same contents, different insertion order
        .{ .key = "gamma", .value = .{ .boolean = true } },
        .{ .key = "alpha", .value = .{ .unsigned = 1 } },
        .{ .key = "beta", .value = .{ .string = "x" } },
    };
    var oa = try sign(allocator, .{ .map = &a_entries }, kp);
    defer oa.deinit(allocator);
    var ob = try sign(allocator, .{ .map = &b_entries }, kp);
    defer ob.deinit(allocator);

    try testing.expectEqualSlices(u8, oa.canonical, ob.canonical); // canonical bytes identical
    try testing.expectEqual(oa.signature, ob.signature); // => identical signatures
    try testing.expect(verify(oa, null) and verify(ob, null));
}

test "tampered canonical bytes fail verification" {
    const allocator = testing.allocator;
    const kp = try key(0x04);
    var entries = [_]MapEntry{.{ .key = "k", .value = .{ .unsigned = 42 } }};
    var obj = try sign(allocator, .{ .map = &entries }, kp);
    defer obj.deinit(allocator);

    obj.canonical[obj.canonical.len - 1] ^= 0x01;
    try testing.expect(!verify(obj, null));
}

test "decodeValue recovers the signed object" {
    const allocator = testing.allocator;
    const kp = try key(0x05);
    var entries = [_]MapEntry{
        .{ .key = "name", .value = .{ .string = "mizuchi" } },
        .{ .key = "n", .value = .{ .unsigned = 9 } },
    };
    var obj = try sign(allocator, .{ .map = &entries }, kp);
    defer obj.deinit(allocator);
    try testing.expect(verify(obj, null));

    var decoded = try decodeValue(allocator, obj);
    defer decoded.deinit(allocator);
    try testing.expect(decoded == .map);
    try testing.expectEqual(@as(usize, 2), decoded.map.len);
    // canonical order sorts keys: "n" < "name"
    try testing.expectEqualStrings("n", decoded.map[0].key);
    try testing.expectEqual(@as(u64, 9), decoded.map[0].value.unsigned);
}
