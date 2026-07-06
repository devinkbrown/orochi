// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Known-answer tests for TSUMUGI key exchange.
const std = @import("std");
const kx = @import("kx.zig");

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "RFC 7748 section 5.2 X25519 scalar multiplication vectors" {
    const Vector = struct {
        scalar: [kx.X25519Kx.secret_len]u8,
        u_coordinate: kx.PublicKey,
        output: [kx.X25519Kx.shared_len]u8,
    };

    const vectors = [_]Vector{
        .{
            .scalar = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            .u_coordinate = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
            .output = hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
        },
        .{
            .scalar = hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
            .u_coordinate = hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
            .output = hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
        },
    };

    for (vectors) |vector| {
        var scalar = kx.SecretKey.init(vector.scalar);
        defer scalar.wipe();

        var shared = try kx.X25519Kx.sharedSecret(&scalar, vector.u_coordinate);
        defer shared.wipe();

        const shared_bytes = shared.declassify();
        try std.testing.expectEqualSlices(u8, &vector.output, &shared_bytes);
    }
}

test "RFC 7748 section 5.2 X25519 iterative test vectors (1 and 1000 iterations)" {
    // RFC 7748 §5.2 iterated procedure: both k (scalar) and u (u-coordinate)
    // start at the encoded byte string 0x09 followed by 31 zero bytes. Each
    // round computes result = X25519(k, u), then sets u = k and k = result.
    // The scalar clamping mandated by RFC 7748 happens inside X25519 itself.
    var k: [32]u8 = [_]u8{0} ** 32;
    k[0] = 9;
    var u: [32]u8 = k;

    // Independent published answers from RFC 7748 §5.2.
    const after_1 = hex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    const after_1000 = hex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        var scalar = kx.SecretKey.init(k);
        defer scalar.wipe();

        var shared = try kx.X25519Kx.sharedSecret(&scalar, u);
        defer shared.wipe();
        const result = shared.declassify();

        u = k;
        k = result;

        if (i == 0) {
            try std.testing.expectEqualSlices(u8, &after_1, &k);
        }
    }
    try std.testing.expectEqualSlices(u8, &after_1000, &k);

    // The RFC also gives a 1,000,000-iteration answer
    // (7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424);
    // it is intentionally omitted here as far too slow for the unit suite.
}

test "X25519Kx derives the same shared secret on both sides" {
    var alice = try kx.X25519Kx.generateDeterministic(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    defer alice.wipe();
    var bob = try kx.X25519Kx.generateDeterministic(hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    defer bob.wipe();

    var alice_shared = try kx.X25519Kx.sharedSecret(&alice.secret_key, bob.public_key);
    defer alice_shared.wipe();
    var bob_shared = try kx.X25519Kx.sharedSecret(&bob.secret_key, alice.public_key);
    defer bob_shared.wipe();

    const alice_bytes = alice_shared.declassify();
    const bob_bytes = bob_shared.declassify();
    try std.testing.expectEqualSlices(u8, &alice_bytes, &bob_bytes);
}

test "HybridKx deterministic encapsulation and shared-secret agreement" {
    var responder_seed: [kx.HybridKx.seed_len]u8 = [_]u8{0} ** kx.HybridKx.seed_len;
    for (&responder_seed, 0..) |*byte, i| {
        byte.* = @intCast((i * 17 + 0x31) & 0xff);
    }
    var responder = try kx.HybridKx.generateDeterministic(responder_seed);
    defer responder.wipe();

    var initiator_x = try kx.X25519Kx.generateDeterministic(hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"));
    defer initiator_x.wipe();

    var encaps_seed: [kx.HybridKx.encaps_seed_len]u8 = [_]u8{0} ** kx.HybridKx.encaps_seed_len;
    for (&encaps_seed, 0..) |*byte, i| {
        byte.* = @intCast((i * 29 + 0x47) & 0xff);
    }

    const transcript = "orochi kx kat deterministic transcript";
    const responder_share = responder.publicShare();

    var first = try kx.HybridKx.encapsulateDeterministic(
        &initiator_x,
        responder_share,
        transcript,
        &encaps_seed,
    );
    defer first.wipe();
    var second = try kx.HybridKx.encapsulateDeterministic(
        &initiator_x,
        responder_share,
        transcript,
        &encaps_seed,
    );
    defer second.wipe();

    try std.testing.expectEqual(first.share.x25519_public_key, second.share.x25519_public_key);
    try std.testing.expectEqual(first.share.mlkem_ciphertext, second.share.mlkem_ciphertext);

    const first_bytes = first.shared_secret.declassify();
    const second_bytes = second.shared_secret.declassify();
    try std.testing.expectEqualSlices(u8, &first_bytes, &second_bytes);

    var responder_shared = try kx.HybridKx.decapsulate(&responder, first.share, transcript);
    defer responder_shared.wipe();
    const responder_bytes = responder_shared.declassify();

    try std.testing.expectEqualSlices(u8, &first_bytes, &responder_bytes);
}
