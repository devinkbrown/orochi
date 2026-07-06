// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Robustness harnesses for the attacker-facing wire parsers.
//!
//! Every function here feeds hostile bytes — pure random and bit-flipped
//! near-valid — to the X.509, TLS-record, and TLS-handshake-message parsers and
//! asserts the ONLY observable outcome is a returned value or a returned error,
//! never a panic (a safety-check trap on OOB / integer overflow / `unreachable`
//! is a real bug and fails the test).
//!
//! Two layers:
//!
//!  1. DETERMINISTIC tests (fixed PRNG seed) that always run in the normal
//!     `zig build test`: pure-random, structured length-prefixed noise, and
//!     bit-flipped-valid-certificate corpora (~44k inputs/run, reproducible).
//!     `feedAll` fans every input out to ALL of the attacker-facing parsers
//!     (X.509, TLS record framing + ciphertext + inner-plaintext, OCSP,
//!     TLS handshake messages, and the SNI extractor); the cert-compression
//!     bomb guard gets its own dedicated deterministic loop below. This layer
//!     is the fuzzing that actually runs in CI and does NOT depend on `--fuzz`.
//!
//!  2. COVERAGE-GUIDED targets (`cov-fuzz:` tests) built on Zig 0.16's builtin
//!     fuzzer via `std.testing.fuzz`. Each wraps one high-value parser so the
//!     fuzzer's coverage feedback can steer mutation into deep parser paths.
//!     Under a plain `zig build test` the fuzz runner only replays each target's
//!     seed corpus plus an empty-string smoke input (bounded, fast — it does NOT
//!     balloon the ~6100-test suite); under `zig build test --fuzz` (or the
//!     dedicated `zig build fuzz --fuzz` step) the SAME targets are meant to run
//!     coverage-guided. See build.zig's `fuzz` step.
//!
//!     TOOLCHAIN NOTE (Zig 0.16.0 as installed here): native `--fuzz` currently
//!     fails to BUILD — not in this file, but in the compiler's own
//!     `compiler/test_runner.zig`, whose `builtin.fuzz`-only error-reporting path
//!     calls `std.debug.writeStackTrace(@errorReturnTrace(), ...)` with a
//!     `*builtin.StackTrace` where `*const debug.StackTrace` is expected (the two
//!     `StackTrace` types diverged in this std). Because that code sits behind
//!     `if (builtin.fuzz)`, it only compiles under `-ffuzz`, so `zig build test`
//!     stays green while `zig build fuzz --fuzz` cannot link. The targets here are
//!     the correct API and become coverage-guided the moment the toolchain is
//!     fixed; until then the deterministic layer above is the operative fuzzer.
const std = @import("std");

const x509 = @import("x509.zig");
const tls12 = @import("tls12.zig");
const tls_record = @import("tls_record.zig");
const ocsp = @import("ocsp.zig");
const tls12_handshake = @import("../proto/tls12_handshake.zig");
const x509_selfsign = @import("../proto/x509_selfsign.zig");
const sni = @import("../proto/sni.zig");
const cert_compression = @import("../proto/cert_compression.zig");
const Ed25519 = std.crypto.sign.Ed25519;

/// Run every parser against one input. A panic inside any of them aborts the
/// test — which is exactly the signal we want. Errors are swallowed; iterators
/// are drained (bounded) so lazy per-element parsing is exercised too. Every
/// parser here is allocation-free on the reject path, so this stays cheap enough
/// to run tens of thousands of times per test. (The cert-compression bomb guard
/// is the one allocating parser; it gets its own bounded loop below.)
fn feedAll(input: []const u8) void {
    _ = x509.parse(input) catch {};
    _ = tls12.completeRecord(input) catch {};
    _ = tls_record.parseCiphertext(input) catch {};
    _ = ocsp.parse(input) catch {};
    _ = sni.extract(input); // returns a Result union, never errors — must never trap
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
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x7c)));
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

test "cert_compression.inflateZlib never panics on hostile input" {
    // The bomb guard is the one allocating wire parser, so it gets a dedicated
    // bounded loop rather than riding in `feedAll`. Feeds a mix of bit-flipped
    // valid zlib (to drive the decompressor's inner paths) and pure-random bytes,
    // each with a declared length spanning below / at / above the cap so the
    // §4 pre-allocation guard, the §5 exact-length guard, and the happy path are
    // all reachable. The testing allocator's leak check backstops every branch.
    const alloc = std.testing.allocator;
    const body = "a certificate body that is worth compressing for the fuzz corpus";
    const valid = try cert_compression.deflateZlib(alloc, body);
    defer alloc.free(valid);

    var prng = std.Random.DefaultPrng.init(0xC0FFEE_D00D_1279);
    const rand = prng.random();
    var scratch: [512]u8 = undefined;
    var i: usize = 0;
    while (i < 4000) : (i += 1) {
        const len = @min(valid.len, scratch.len);
        if (rand.boolean()) {
            @memcpy(scratch[0..len], valid[0..len]);
            const flips = rand.intRangeAtMost(usize, 1, 4);
            var f: usize = 0;
            while (f < flips) : (f += 1) {
                scratch[rand.intRangeLessThan(usize, 0, len)] ^= rand.int(u8);
            }
        } else {
            rand.bytes(scratch[0..len]);
        }
        const declared = rand.intRangeAtMost(usize, 0, cert_compression.max_uncompressed_len + 32);
        if (cert_compression.inflateZlib(alloc, scratch[0..len], declared)) |out| {
            alloc.free(out);
        } else |_| {}
    }

    // Sanity: the pristine stream still round-trips at its true declared length.
    const restored = try cert_compression.inflateZlib(alloc, valid, body.len);
    defer alloc.free(restored);
    try std.testing.expectEqualSlices(u8, body, restored);
}

// ---------------------------------------------------------------------------
// Coverage-guided targets (Zig 0.16 `std.testing.fuzz`).
//
// Each `oneInput` is a `fn (context, *std.testing.Smith) anyerror!void`: it pulls
// a variable-length byte string from the Smith (which, under the fuzzer, is
// driven by coverage-guided mutation; under a normal test run, by the replayed
// seed corpus) and feeds it to exactly one attacker-facing parser. The contract
// is identical to the deterministic tests above: a returned value or error is
// fine; a panic / safety-check trap / UB is a real bug and fails the run.
//
// `slice_cap` bounds the input a single target extracts. Certs and records here
// are all well under this; the fuzzer is free to explore the whole range.
// ---------------------------------------------------------------------------

const slice_cap = 4096;

/// Frame a raw payload as a Smith corpus seed: `smith.slice` reads a leading
/// little-endian u32 length, then that many bytes, so a corpus entry that should
/// decode to `payload` must be `<u32 len><payload>`. Returns a slice of `out`.
fn frameSlice(out: []u8, payload: []const u8) []const u8 {
    std.debug.assert(out.len >= 4 + payload.len);
    std.mem.writeInt(u32, out[0..4], @intCast(payload.len), .little);
    @memcpy(out[4..][0..payload.len], payload);
    return out[0 .. 4 + payload.len];
}

fn oneX509(_: void, smith: *std.testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [slice_cap]u8 = undefined;
    const n = smith.slice(&buf);
    _ = x509.parse(buf[0..n]) catch {};
}

fn oneTlsRecord(_: void, smith: *std.testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [slice_cap]u8 = undefined;
    const n = smith.slice(&buf);
    // Outer TLSCiphertext framing check and the daemon's record framer.
    _ = tls_record.parseCiphertext(buf[0..n]) catch {};
    _ = tls12.completeRecord(buf[0..n]) catch {};
    // Inner-plaintext content-type/padding scan (mutates its buffer in place).
    _ = tls_record.decodeInnerPlaintext(buf[0..n]) catch {};
}

fn oneOcsp(_: void, smith: *std.testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [slice_cap]u8 = undefined;
    const n = smith.slice(&buf);
    _ = ocsp.parse(buf[0..n]) catch {};
}

fn oneHandshake(_: void, smith: *std.testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [slice_cap]u8 = undefined;
    const n = smith.slice(&buf);
    const input = buf[0..n];
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

fn oneCertCompression(_: void, smith: *std.testing.Smith) anyerror!void {
    @disableInstrumentation();
    // Exercise the RFC 8879 §4/§5 bomb guard across the whole declared-length
    // range, including values above the cap (which must be rejected BEFORE any
    // allocation). +16 so the fuzzer also visits the reject-above-cap branch.
    const declared: u32 = smith.valueRangeAtMost(u32, 0, cert_compression.max_uncompressed_len + 16);
    var buf: [slice_cap]u8 = undefined;
    const n = smith.slice(&buf);
    const out = cert_compression.inflateZlib(std.testing.allocator, buf[0..n], declared) catch return;
    // A successful inflate returns an owned buffer; free it so the testing
    // allocator's leak check (run at test end during corpus replay) stays clean.
    std.testing.allocator.free(out);
}

fn oneSni(_: void, smith: *std.testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [slice_cap]u8 = undefined;
    const n = smith.slice(&buf);
    // `extract` never returns an error (it maps every failure to `.malformed`);
    // the property under test is that it never traps on hostile bytes.
    _ = sni.extract(buf[0..n]);
    _ = sni.extractOptional(buf[0..n]);
}

test "cov-fuzz: x509.parse never traps on arbitrary DER" {
    // Seed with a real self-signed certificate so the fuzzer starts from a
    // structurally-valid TLV tree and mutates inward.
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x3a)));
    var der_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&der_buf, .{
        .common_name = "cov.fuzz.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x44, 0x02 },
        .key_pair = kp,
        .dns_names = &.{"cov.fuzz.test"},
        .is_ca = true,
        .path_len = 2,
    });
    var seed_buf: [1100]u8 = undefined;
    const seed = frameSlice(&seed_buf, der);
    try std.testing.fuzz({}, oneX509, .{ .corpus = &.{seed} });
}

test "cov-fuzz: tls_record parsers never trap on arbitrary bytes" {
    // A well-formed application_data record header + 3-byte fragment.
    var s0: [32]u8 = undefined;
    const seed = frameSlice(&s0, &.{ 0x17, 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC });
    try std.testing.fuzz({}, oneTlsRecord, .{ .corpus = &.{seed} });
}

test "cov-fuzz: ocsp.parse never traps on arbitrary DER" {
    // Two small structural seeds that reach distinct outer-response branches.
    var s0: [32]u8 = undefined;
    var s1: [32]u8 = undefined;
    const seed0 = frameSlice(&s0, &.{ 0x30, 0x08, 0x0A, 0x01, 0x01, 0xA0, 0x03, 0x30, 0x01, 0x00 });
    const seed1 = frameSlice(&s1, &.{ 0x30, 0x03, 0x0A, 0x01, 0x00 });
    try std.testing.fuzz({}, oneOcsp, .{ .corpus = &.{ seed0, seed1 } });
}

test "cov-fuzz: tls12 handshake parsers never trap on arbitrary bytes" {
    // A minimal but structurally-valid ClientHello body (no handshake header:
    // `parseClientHello` consumes the body directly).
    const ch_body = [_]u8{ 0x03, 0x03 } ++ @as([32]u8, @splat(0)) ++ // version + random
        [_]u8{0x00} ++ // session_id length
        [_]u8{ 0x00, 0x02, 0x00, 0x2f } ++ // cipher_suites: len + TLS_RSA_WITH_AES_128_CBC_SHA
        [_]u8{ 0x01, 0x00 } ++ // compression_methods: len + null
        [_]u8{ 0x00, 0x00 }; // extensions: len 0
    var s0: [128]u8 = undefined;
    const seed = frameSlice(&s0, &ch_body);
    try std.testing.fuzz({}, oneHandshake, .{ .corpus = &.{seed} });
}

test "cov-fuzz: cert_compression.inflateZlib bomb guard never traps" {
    // Seed: <u64 declared_len><u32 compressed_len><compressed>. The declared
    // length is pulled first (Smith reads 8 bytes for an integer), then the
    // compressed slice. Setting declared == body.len drives the happy path;
    // the fuzzer mutates toward the bomb-guard reject branches from there.
    const body = "certificate-shaped body for the zlib fuzz seed \x00\x01\x02\x03";
    const compressed = try cert_compression.deflateZlib(std.testing.allocator, body);
    defer std.testing.allocator.free(compressed);

    var seed_buf: [512]u8 = undefined;
    std.mem.writeInt(u64, seed_buf[0..8], body.len, .little);
    std.mem.writeInt(u32, seed_buf[8..12], @intCast(compressed.len), .little);
    @memcpy(seed_buf[12..][0..compressed.len], compressed);
    const seed = seed_buf[0 .. 12 + compressed.len];
    try std.testing.fuzz({}, oneCertCompression, .{ .corpus = &.{seed} });
}

test "cov-fuzz: sni.extract never traps on arbitrary bytes" {
    // A bare ClientHello (handshake type 1) carrying a single server_name
    // extension for "a" — the deepest reachable path in the SNI walker.
    const sni_ext_data = [_]u8{ 0x00, 0x04, 0x00, 0x00, 0x01, 'a' }; // list_len + name_type + name_len + name
    const sni_ext = [_]u8{ 0x00, 0x00, 0x00, @as(u8, @intCast(sni_ext_data.len)) } ++ sni_ext_data;
    const ch_body = [_]u8{ 0x03, 0x03 } ++ @as([32]u8, @splat(0)) ++
        [_]u8{0x00} ++ // session_id length
        [_]u8{ 0x00, 0x02, 0x00, 0x2f } ++ // cipher_suites
        [_]u8{ 0x01, 0x00 } ++ // compression_methods
        [_]u8{ 0x00, @as(u8, @intCast(sni_ext.len)) } ++ sni_ext; // extensions
    const ch_len = ch_body.len;
    const ch_msg = [_]u8{ 0x01, @intCast((ch_len >> 16) & 0xff), @intCast((ch_len >> 8) & 0xff), @intCast(ch_len & 0xff) } ++ ch_body;
    var s0: [256]u8 = undefined;
    const seed = frameSlice(&s0, &ch_msg);
    try std.testing.fuzz({}, oneSni, .{ .corpus = &.{seed} });
}
