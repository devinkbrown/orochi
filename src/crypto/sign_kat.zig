// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! RFC 8032 Section 7.1 known-answer tests for Ed25519 signing.
const std = @import("std");
const sign = @import("sign.zig");

const testing = std.testing;

const TestVector = struct {
    seed: sign.Seed,
    public_key: sign.PublicKey,
    message: []const u8,
    signature: sign.Signature,
};

const rfc8032_test_1 = TestVector{
    .seed = hex("9d61b19deffd5a60ba844af492ec2cc4" ++
        "4449c5697b326919703bac031cae7f60"),
    .public_key = hex("d75a980182b10ab7d54bfed3c964073a" ++
        "0ee172f3daa62325af021a68f707511a"),
    .message = &hex(""),
    .signature = hex("e5564300c360ac729086e2cc806e828a" ++
        "84877f1eb8e5d974d873e06522490155" ++
        "5fb8821590a33bacc61e39701cf9b46b" ++
        "d25bf5f0595bbe24655141438e7a100b"),
};

const rfc8032_test_3 = TestVector{
    .seed = hex("c5aa8df43f9f837bedb7442f31dcb7b1" ++
        "66d38535076f094b85ce3a2e0b4458f7"),
    .public_key = hex("fc51cd8e6218a1a38da47ed00230f058" ++
        "0816ed13ba3303ac5deb911548908025"),
    .message = &hex("af82"),
    .signature = hex("6291d657deec24024827e69c3abe01a3" ++
        "0ce548a284743a445e3680d7db5ac3ac" ++
        "18ff9b538d16f290ae67f760984dc659" ++
        "4a7c15e9716ed28dc027beceea1ec40a"),
};

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    comptime {
        if (s.len % 2 != 0) @compileError("hex input must have an even length");
    }

    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn expectVerifyRejected(msg: []const u8, sig: sign.Signature, public_key: sign.PublicKey) !void {
    const ok = sign.verify(msg, sig, public_key) catch return;
    try testing.expect(!ok);
}

fn expectKatMatches(vector: TestVector) !void {
    var kp = try sign.KeyPair.fromSeed(vector.seed);
    defer kp.deinit();

    try testing.expectEqualSlices(u8, &vector.public_key, &kp.public_key);

    const sig = try kp.sign(vector.message);
    try testing.expectEqualSlices(u8, &vector.signature, &sig);
    try testing.expect(try sign.verify(vector.message, sig, vector.public_key));

    var bad_sig = sig;
    bad_sig[0] ^= 0x01;
    try expectVerifyRejected(vector.message, bad_sig, vector.public_key);
}

test "RFC 8032 Section 7.1 Ed25519 empty-message vector" {
    try expectKatMatches(rfc8032_test_1);
}

test "RFC 8032 Section 7.1 Ed25519 multi-byte-message vector" {
    try expectKatMatches(rfc8032_test_3);

    var bad_msg = [_]u8{ 0xaf, 0x82 };
    bad_msg[1] ^= 0x01;
    try expectVerifyRejected(&bad_msg, rfc8032_test_3.signature, rfc8032_test_3.public_key);
}

test {
    testing.refAllDecls(@This());
}
