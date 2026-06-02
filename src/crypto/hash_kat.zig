//! Official known-answer tests for the typed hash, HMAC, and HKDF layer.
//!
//! Vectors are byte-exact from FIPS 180-4 SHA-2 examples, RFC 4231 HMAC-SHA256,
//! and RFC 5869 HKDF-SHA256 Appendix A.1.
const std = @import("std");
const hash = @import("hash.zig");

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "FIPS 180-4 SHA-2 digests for abc" {
    const sha256_expected = hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const sha256_actual = hash.Sha256.hash("abc");
    try std.testing.expectEqualSlices(u8, &sha256_expected, &sha256_actual);

    const sha384_expected = hex("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed" ++
        "8086072ba1e7cc2358baeca134c825a7");
    const sha384_actual = hash.Sha384.hash("abc");
    try std.testing.expectEqualSlices(u8, &sha384_expected, &sha384_actual);

    const sha512_expected = hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" ++
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    const sha512_actual = hash.Sha512.hash("abc");
    try std.testing.expectEqualSlices(u8, &sha512_expected, &sha512_actual);
}

test "RFC 4231 HMAC-SHA256 test case 1" {
    const key = [_]u8{0x0b} ** 20;
    const actual = hash.HmacSha256.create(&key, "Hi There");
    const expected = hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "RFC 5869 HKDF-SHA256 test case 1" {
    const ikm = [_]u8{0x0b} ** 22;
    const salt = hex("000102030405060708090a0b0c");
    const info = hex("f0f1f2f3f4f5f6f7f8f9");

    const prk = hash.HkdfSha256.extractRaw(&salt, &ikm);
    const prk_actual = prk.declassify();
    const prk_expected = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    try std.testing.expectEqualSlices(u8, &prk_expected, &prk_actual);

    var okm: [42]u8 = undefined;
    try hash.HkdfSha256.expand(&prk, &info, &okm);
    const okm_expected = hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" ++
        "34007208d5b887185865");
    try std.testing.expectEqualSlices(u8, &okm_expected, &okm);
}
