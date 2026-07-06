// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS 1.2 Pseudo-Random Function (PRF) per RFC 5246 §5, plus the key
//! derivations layered on top of it (master secret, key block, Finished
//! verify_data).
//!
//! The PRF is defined as:
//!
//!     PRF(secret, label, seed) = P_hash(secret, label || seed)
//!
//! where P_hash expands a secret into arbitrarily many bytes using HMAC:
//!
//!     A(0) = seed
//!     A(i) = HMAC(secret, A(i-1))
//!     P_hash(secret, seed) = HMAC(secret, A(1) || seed) ||
//!                            HMAC(secret, A(2) || seed) || ...
//!
//! TLS 1.2 uses P_SHA256 for most cipher suites and P_SHA384 for SHA384
//! suites (RFC 5246 §5, RFC 5288). This module is pure: it only touches
//! `std.crypto` and performs no I/O, clock, or RNG access.

const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;

/// Length, in bytes, of a TLS 1.2 master secret.
pub const master_secret_len = 48;

/// Length, in bytes, of Finished verify_data (RFC 5246 §7.4.9).
pub const verify_data_len = 12;

/// Generic PRF: out = P_hash(secret, label || seed). The label and seed are
/// fed to the HMAC incrementally so no intermediate concatenation buffer is
/// allocated.
fn prf(comptime Hmac: type, secret: []const u8, label: []const u8, seed: []const u8, out: []u8) void {
    const mac_len = Hmac.mac_length;

    // A(1) = HMAC(secret, label || seed)
    var a: [mac_len]u8 = undefined;
    {
        var ctx = Hmac.init(secret);
        ctx.update(label);
        ctx.update(seed);
        ctx.final(&a);
    }

    var written: usize = 0;
    while (written < out.len) {
        // block = HMAC(secret, A(i) || label || seed)
        var block: [mac_len]u8 = undefined;
        var ctx = Hmac.init(secret);
        ctx.update(&a);
        ctx.update(label);
        ctx.update(seed);
        ctx.final(&block);

        const take = @min(mac_len, out.len - written);
        @memcpy(out[written .. written + take], block[0..take]);
        written += take;

        if (written < out.len) {
            var next: [mac_len]u8 = undefined;
            Hmac.create(&next, &a, secret);
            a = next;
        }
    }
}

/// PRF using P_SHA256. `out` may be any length.
pub fn prfSha256(secret: []const u8, label: []const u8, seed: []const u8, out: []u8) void {
    prf(HmacSha256, secret, label, seed, out);
}

/// PRF using P_SHA384. `out` may be any length.
pub fn prfSha384(secret: []const u8, label: []const u8, seed: []const u8, out: []u8) void {
    prf(HmacSha384, secret, label, seed, out);
}

/// Dispatch to the SHA256 or SHA384 PRF based on the cipher suite hash.
fn prfDispatch(secret: []const u8, label: []const u8, seed: []const u8, sha384: bool, out: []u8) void {
    switch (sha384) {
        true => prfSha384(secret, label, seed, out),
        false => prfSha256(secret, label, seed, out),
    }
}

/// Derive the master secret (RFC 5246 §8.1):
///
///     master_secret = PRF(pre_master_secret, "master secret",
///                         client_random || server_random)[0..48]
pub fn masterSecret(
    pre_master: []const u8,
    client_random: [32]u8,
    server_random: [32]u8,
    sha384: bool,
) [master_secret_len]u8 {
    var seed: [64]u8 = undefined;
    @memcpy(seed[0..32], &client_random);
    @memcpy(seed[32..64], &server_random);

    var out: [master_secret_len]u8 = undefined;
    prfDispatch(pre_master, "master secret", &seed, sha384, &out);
    return out;
}

/// Derive a key block of arbitrary length (RFC 5246 §6.3):
///
///     key_block = PRF(master_secret, "key expansion",
///                     server_random || client_random)
///
/// Note the seed order is server_random || client_random, the reverse of
/// the master-secret derivation.
pub fn keyBlock(
    master: [master_secret_len]u8,
    server_random: [32]u8,
    client_random: [32]u8,
    sha384: bool,
    out: []u8,
) void {
    var seed: [64]u8 = undefined;
    @memcpy(seed[0..32], &server_random);
    @memcpy(seed[32..64], &client_random);

    prfDispatch(&master, "key expansion", &seed, sha384, out);
}

/// Compute Finished verify_data (RFC 5246 §7.4.9):
///
///     verify_data = PRF(master_secret, finished_label, handshake_hash)[0..12]
///
/// `finished_label` is "client finished" or "server finished".
pub fn verifyData(
    master: [master_secret_len]u8,
    finished_label: []const u8,
    handshake_hash: []const u8,
    sha384: bool,
    out: *[verify_data_len]u8,
) void {
    prfDispatch(&master, finished_label, handshake_hash, sha384, out);
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = std.testing;

test "prfSha256 fills the requested output length exactly" {
    // Arrange
    const secret = "secret";
    const label = "label";
    const seed = "seed";
    var out: [100]u8 = undefined;

    // Act
    prfSha256(secret, label, seed, &out);

    // Assert: arbitrary length (not a multiple of 32) is fully written.
    // At least one byte past the first HMAC block must be non-zero with
    // overwhelming probability, proving expansion past block 1.
    var any_nonzero = false;
    for (out[32..]) |b| {
        if (b != 0) any_nonzero = true;
    }
    try testing.expect(any_nonzero);
}

test "P_SHA256 A() iteration matches a raw-HMAC re-derivation" {
    // Arrange: reproduce P_hash(secret, label||seed) by hand using only the
    // raw HMAC primitive, then compare to the module output. This validates
    // the A(0)=seed, A(i)=HMAC(secret, A(i-1)) recurrence and the block
    // concatenation.
    const secret = "topsecretkey";
    const label = "test label";
    const seed = "test seed";

    // Build the combined label||seed that the PRF treats as its P_hash seed.
    var combined: [19]u8 = undefined; // len("test label")+len("test seed")
    @memcpy(combined[0..10], label);
    @memcpy(combined[10..19], seed);

    const mac_len = HmacSha256.mac_length;

    // A(1) = HMAC(secret, combined)
    var a1: [mac_len]u8 = undefined;
    HmacSha256.create(&a1, &combined, secret);
    // A(2) = HMAC(secret, A(1))
    var a2: [mac_len]u8 = undefined;
    HmacSha256.create(&a2, &a1, secret);

    // block1 = HMAC(secret, A(1) || combined)
    var block1: [mac_len]u8 = undefined;
    {
        var ctx = HmacSha256.init(secret);
        ctx.update(&a1);
        ctx.update(&combined);
        ctx.final(&block1);
    }
    // block2 = HMAC(secret, A(2) || combined)
    var block2: [mac_len]u8 = undefined;
    {
        var ctx = HmacSha256.init(secret);
        ctx.update(&a2);
        ctx.update(&combined);
        ctx.final(&block2);
    }

    var expected: [2 * mac_len]u8 = undefined;
    @memcpy(expected[0..mac_len], &block1);
    @memcpy(expected[mac_len .. 2 * mac_len], &block2);

    // Act
    var out: [2 * mac_len]u8 = undefined;
    prfSha256(secret, label, seed, &out);

    // Assert
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "prfSha384 single-block output equals one raw HMAC-SHA384 block" {
    // Arrange
    const secret = "k384";
    const label = "lbl";
    const seed = "sd";
    const mac_len = HmacSha384.mac_length; // 48

    var combined: [5]u8 = undefined;
    @memcpy(combined[0..3], label);
    @memcpy(combined[3..5], seed);

    var a1: [mac_len]u8 = undefined;
    HmacSha384.create(&a1, &combined, secret);
    var expected: [mac_len]u8 = undefined;
    {
        var ctx = HmacSha384.init(secret);
        ctx.update(&a1);
        ctx.update(&combined);
        ctx.final(&expected);
    }

    // Act: request exactly one block worth of output.
    var out: [mac_len]u8 = undefined;
    prfSha384(secret, label, seed, &out);

    // Assert
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "masterSecret produces 48 bytes and is deterministic" {
    // Arrange
    const pms = @as([48]u8, @splat(0xAB));
    const cr = @as([32]u8, @splat(0x01));
    const sr = @as([32]u8, @splat(0x02));

    // Act
    const ms1 = masterSecret(&pms, cr, sr, false);
    const ms2 = masterSecret(&pms, cr, sr, false);

    // Assert
    try testing.expectEqual(@as(usize, 48), ms1.len);
    try testing.expectEqualSlices(u8, &ms1, &ms2);

    // SHA384 variant differs from SHA256 variant for the same inputs.
    const ms384 = masterSecret(&pms, cr, sr, true);
    try testing.expect(!std.mem.eql(u8, &ms1, &ms384));
}

test "masterSecret equals direct PRF(\"master secret\", cr||sr)" {
    // Arrange
    const pms = @as([48]u8, @splat(0x5A));
    const cr = @as([32]u8, @splat(0x11));
    const sr = @as([32]u8, @splat(0x22));

    var seed: [64]u8 = undefined;
    @memcpy(seed[0..32], &cr);
    @memcpy(seed[32..64], &sr);
    var expected: [48]u8 = undefined;
    prfSha256(&pms, "master secret", &seed, &expected);

    // Act
    const ms = masterSecret(&pms, cr, sr, false);

    // Assert
    try testing.expectEqualSlices(u8, &expected, &ms);
}

test "keyBlock fills an arbitrary length and uses server||client seed order" {
    // Arrange
    const master = @as([48]u8, @splat(0xCD));
    const cr = @as([32]u8, @splat(0x33));
    const sr = @as([32]u8, @splat(0x44));
    var block: [104]u8 = undefined; // 2*MAC + IVs sized, arbitrary length

    // Act
    keyBlock(master, sr, cr, false, &block);

    // Assert: the seed order is server_random || client_random. Compute the
    // PRF directly with that order and confirm it matches.
    var seed: [64]u8 = undefined;
    @memcpy(seed[0..32], &sr);
    @memcpy(seed[32..64], &cr);
    var expected: [104]u8 = undefined;
    prfSha256(&master, "key expansion", &seed, &expected);
    try testing.expectEqualSlices(u8, &expected, &block);

    // And the reversed order yields a different block, proving order matters.
    var swapped: [104]u8 = undefined;
    keyBlock(master, cr, sr, false, &swapped);
    try testing.expect(!std.mem.eql(u8, &block, &swapped));
}

test "verifyData is deterministic and differs for client vs server label" {
    // Arrange
    const master = @as([48]u8, @splat(0xEF));
    const handshake_hash = @as([32]u8, @splat(0x77));

    // Act
    var client_vd: [verify_data_len]u8 = undefined;
    var client_vd2: [verify_data_len]u8 = undefined;
    var server_vd: [verify_data_len]u8 = undefined;
    verifyData(master, "client finished", &handshake_hash, false, &client_vd);
    verifyData(master, "client finished", &handshake_hash, false, &client_vd2);
    verifyData(master, "server finished", &handshake_hash, false, &server_vd);

    // Assert
    try testing.expectEqual(@as(usize, 12), client_vd.len);
    try testing.expectEqualSlices(u8, &client_vd, &client_vd2); // deterministic
    try testing.expect(!std.mem.eql(u8, &client_vd, &server_vd)); // label matters
}
