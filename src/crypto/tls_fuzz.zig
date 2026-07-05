// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Robustness harnesses for the attacker-facing wire parsers.
//!
//! Every function here feeds hostile bytes — pure random and bit-flipped
//! near-valid — to the X.509, TLS-record, and TLS-handshake-message parsers and
//! asserts the ONLY observable outcome is a returned value or a returned error,
//! never a panic (a safety-check trap on OOB / integer overflow / `unreachable`
//! is a real bug and fails the test). These are DETERMINISTIC (fixed PRNG seed)
//! so they run in the normal `zig build test` and are reproducible; upgrading to
//! coverage-guided `--fuzz` (std.testing.fuzz / Smith) is a follow-up.
const std = @import("std");

const x509 = @import("x509.zig");
const tls12 = @import("tls12.zig");
const tls12_handshake = @import("../proto/tls12_handshake.zig");
const x509_selfsign = @import("../proto/x509_selfsign.zig");
const Ed25519 = std.crypto.sign.Ed25519;

/// Run every parser against one input. A panic inside any of them aborts the
/// test — which is exactly the signal we want. Errors are swallowed; iterators
/// are drained (bounded) so lazy per-element parsing is exercised too.
fn feedAll(input: []const u8) void {
    _ = x509.parse(input) catch {};
    _ = tls12.completeRecord(input) catch {};
    _ = tls12_handshake.parseClientHello(input) catch {};
    _ = tls12_handshake.parseServerHello(input) catch {};
    _ = tls12_handshake.parseHandshakeHeader(input) catch {};
    _ = tls12_handshake.parseNewSessionTicket(input) catch {};
    if (tls12_handshake.parseCertificate(input)) |it| {
        var iter = it;
        var guard: usize = 0;
        while (guard < 64) : (guard += 1) {
            const nxt = iter.next() catch break;
            if (nxt == null) break;
        }
    } else |_| {}
}

test "wire parsers never panic on random input" {
    var prng = std.Random.DefaultPrng.init(0xA5A5_1234_DEAD_BEEF);
    const rand = prng.random();
    var buf: [2048]u8 = undefined;
    var i: usize = 0;
    while (i < 12_000) : (i += 1) {
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        rand.bytes(buf[0..len]);
        feedAll(buf[0..len]);
    }
}

test "wire parsers never panic on structured length-prefixed noise" {
    // Random bytes rarely reach past the outermost length field. Bias toward
    // plausible DER/TLS shapes: a leading tag/type byte, then a length, then
    // random contents — this drives the parsers deeper into their bounds logic.
    var prng = std.Random.DefaultPrng.init(0x0BADC0DE_F00DFACE);
    const rand = prng.random();
    var buf: [2048]u8 = undefined;
    var i: usize = 0;
    while (i < 12_000) : (i += 1) {
        // Byte 0: a common structural tag (SEQUENCE / handshake type / content type).
        buf[0] = rand.intRangeAtMost(u8, 0, 0x30);
        // Bytes 1..3: a 2- or 3-byte length that may over- or under-run the buffer.
        buf[1] = rand.int(u8);
        buf[2] = rand.int(u8);
        buf[3] = rand.int(u8);
        const len = rand.intRangeAtMost(usize, 4, buf.len);
        rand.bytes(buf[4..len]);
        feedAll(buf[0..len]);
    }
}

test "x509.parse never panics on bit-flipped valid certificates" {
    // A real, structurally-valid cert mutated one byte at a time reaches parser
    // paths pure random never does (valid outer TLV, corrupt inner fields).
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x7c} ** 32);
    var der_buf: [1024]u8 = undefined;
    const base = try x509_selfsign.buildSelfSigned(&der_buf, .{
        .common_name = "fuzz.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x33, 0x01 },
        .key_pair = kp,
        .dns_names = &.{"fuzz.test"},
        .is_ca = true,
        .path_len = 3,
    });
    try std.testing.expect((x509.parse(base) catch null) != null); // sanity: base parses

    var prng = std.Random.DefaultPrng.init(0xFACEFEED_1357_2468);
    const rand = prng.random();
    var scratch: [1024]u8 = undefined;
    var i: usize = 0;
    while (i < 20_000) : (i += 1) {
        @memcpy(scratch[0..base.len], base);
        // Flip 1..4 random bytes.
        const flips = rand.intRangeAtMost(usize, 1, 4);
        var f: usize = 0;
        while (f < flips) : (f += 1) {
            const pos = rand.intRangeLessThan(usize, 0, base.len);
            scratch[pos] ^= rand.int(u8);
        }
        _ = x509.parse(scratch[0..base.len]) catch {};
    }
}
