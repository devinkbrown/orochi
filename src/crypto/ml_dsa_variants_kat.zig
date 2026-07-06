// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Independent known-answer tests for ML-DSA-44 and ML-DSA-87 (FIPS 204)
//! signature verification — the two parameter sets beyond ML-DSA-65 (whose KATs
//! live, frozen, in `ml_dsa_kat.zig`).
//!
//! The vectors embedded here are NIST ACVP FIPS 204 `ML-DSA-sigVer` test cases
//! (parameter sets ML-DSA-44 and ML-DSA-87) taken verbatim from
//! `usnistgov/ACVP-Server:gen-val/json-files/ML-DSA-sigVer-FIPS204/
//! internalProjection.json`. They are INDEPENDENT published vectors — a triple
//! of (public key, message, signature) with a NIST-supplied accept/reject
//! verdict — NOT values this code produced. That independence is the whole
//! point: a plausible-but-wrong lattice verifier passes a self-consistency
//! round-trip but fails these ACVP accept vectors.
//!
//! Per set, two ACVP test groups are covered:
//!   * external / pure  → `ml_dsa.verify(P, pk, msg, ctx, sig)`, the full public
//!     API including the 0x00‖len(ctx)‖ctx domain prefix.
//!   * internal         → `ml_dsa.verifyInternalFor(P, pk, M′, sig)`.
//!
//! Reject cases span every ACVP failure class: modified message, modified z,
//! modified commitment (c̃), and modified hint.
//!
//! X.509 dispatch note: unlike the ML-DSA-65 ACVP group, the 44/87 external
//! groups contain NO empty-context accept vector (the sole empty-context case in
//! each is a reject), so a fully NIST-backed empty-context *accept* through
//! `verifyCertSignature` is not available for these sets. The dispatch test
//! therefore proves the wiring another way: positive key extraction, exact-OID
//! routing, empty-context injection, plus BadSignature/InvalidKey fail-closed —
//! and the accept-path lattice math is the same code the (KAT-verified) external
//! accept vectors exercise via `ml_dsa.verify`.

const std = @import("std");
const ml_dsa = @import("ml_dsa.zig");
const x509 = @import("x509.zig");
const x509_verify = @import("x509_verify.zig");
const testing = std.testing;

const vectors_44 = @embedFile("ml_dsa44_sigver_acvp.txt");
const vectors_87 = @embedFile("ml_dsa87_sigver_acvp.txt");

/// DER OID content bytes (value only) for each parameter set's AlgorithmIdentifier.
const oid_44 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 };
const oid_87 = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13 };

const Mode = enum { external, internal };

const Vector = struct {
    mode: Mode,
    expect: bool,
    tc: []const u8,
    reason: []const u8,
    pk: []u8,
    ctx: []u8,
    msg: []u8,
    sig: []u8,
};

/// Decode a lowercase-hex field into freshly allocated bytes.
fn hexAlloc(a: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try a.alloc(u8, hex.len / 2);
    errdefer a.free(out);
    const decoded = try std.fmt.hexToBytes(out, hex);
    std.debug.assert(decoded.len == out.len);
    return out;
}

/// Parse the embedded record file into a heap-owned list of vectors. Each record
/// is a block of `key:value` lines separated by a `==` line; `#` lines are
/// comments.
fn parseVectors(a: std.mem.Allocator, vectors_txt: []const u8) !std.ArrayList(Vector) {
    var list: std.ArrayList(Vector) = .empty;
    errdefer {
        for (list.items) |v| freeVector(a, v);
        list.deinit(a);
    }

    var lines = std.mem.splitScalar(u8, vectors_txt, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        if (std.mem.eql(u8, line, "==")) {
            // Append the empty record up front so a mid-record allocation failure
            // still leaves it owned by `list` for the errdefer to free.
            try list.append(a, .{
                .mode = .internal,
                .expect = false,
                .tc = "",
                .reason = "",
                .pk = &.{},
                .ctx = &.{},
                .msg = &.{},
                .sig = &.{},
            });
            continue;
        }
        if (list.items.len == 0) return error.BadRecord; // field before any '=='
        const cur = &list.items[list.items.len - 1];
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.BadRecord;
        const key = line[0..colon];
        const val = line[colon + 1 ..];
        if (std.mem.eql(u8, key, "mode")) {
            cur.mode = if (std.mem.eql(u8, val, "external")) .external else .internal;
        } else if (std.mem.eql(u8, key, "expect")) {
            cur.expect = std.mem.eql(u8, val, "1");
        } else if (std.mem.eql(u8, key, "tc")) {
            cur.tc = val;
        } else if (std.mem.eql(u8, key, "reason")) {
            cur.reason = val;
        } else if (std.mem.eql(u8, key, "pk")) {
            cur.pk = try hexAlloc(a, val);
        } else if (std.mem.eql(u8, key, "ctx")) {
            cur.ctx = try hexAlloc(a, val);
        } else if (std.mem.eql(u8, key, "msg")) {
            cur.msg = try hexAlloc(a, val);
        } else if (std.mem.eql(u8, key, "sig")) {
            cur.sig = try hexAlloc(a, val);
        } else return error.BadRecord;
    }
    return list;
}

fn freeVector(a: std.mem.Allocator, v: Vector) void {
    a.free(v.pk);
    a.free(v.ctx);
    a.free(v.msg);
    a.free(v.sig);
}

fn runVector(comptime P: ml_dsa.Params, v: Vector) bool {
    return switch (v.mode) {
        .external => ml_dsa.verify(P, v.pk, v.msg, v.ctx, v.sig),
        .internal => ml_dsa.verifyInternalFor(P, v.pk, v.msg, v.sig),
    };
}

/// Accept + reject KAT: every ACVP verdict must match, with both verdicts
/// present so "all pass" cannot be vacuous.
fn acvpSuite(comptime P: ml_dsa.Params, vectors_txt: []const u8) !void {
    const a = testing.allocator;
    var vecs = try parseVectors(a, vectors_txt);
    defer {
        for (vecs.items) |v| freeVector(a, v);
        vecs.deinit(a);
    }

    try testing.expect(vecs.items.len >= 30);

    var accept_seen: usize = 0;
    var reject_seen: usize = 0;
    for (vecs.items) |v| {
        const got = runVector(P, v);
        if (got != v.expect) {
            std.debug.print(
                "{s} KAT MISMATCH: mode={s} tc={s} expected={} got={} reason={s}\n",
                .{ P.name, @tagName(v.mode), v.tc, v.expect, got, v.reason },
            );
            return error.KatMismatch;
        }
        if (v.expect) accept_seen += 1 else reject_seen += 1;
    }
    try testing.expect(accept_seen >= 3);
    try testing.expect(reject_seen >= 3);
}

/// Tamper: flipping any accept vector's signature / public key / message rejects.
fn tamperSuite(comptime P: ml_dsa.Params, vectors_txt: []const u8) !void {
    const a = testing.allocator;
    var vecs = try parseVectors(a, vectors_txt);
    defer {
        for (vecs.items) |v| freeVector(a, v);
        vecs.deinit(a);
    }

    var checked: usize = 0;
    for (vecs.items) |v| {
        if (!v.expect) continue; // start from a known-good triple

        try testing.expect(runVector(P, v)); // baseline still verifies

        // Flip one bit of the signature body (skip c̃ so we hit z/hint region).
        {
            const dup = try a.dupe(u8, v.sig);
            defer a.free(dup);
            dup[P.ctilde_len + 1] ^= 0x01;
            var w = v;
            w.sig = dup;
            try testing.expect(!runVector(P, w));
        }
        // Flip one bit of the public key.
        {
            const dup = try a.dupe(u8, v.pk);
            defer a.free(dup);
            dup[100] ^= 0x80;
            var w = v;
            w.pk = dup;
            try testing.expect(!runVector(P, w));
        }
        // Flip one bit of the message (if non-empty).
        if (v.msg.len > 0) {
            const dup = try a.dupe(u8, v.msg);
            defer a.free(dup);
            dup[0] ^= 0x01;
            var w = v;
            w.msg = dup;
            try testing.expect(!runVector(P, w));
        }
        checked += 1;
    }
    try testing.expect(checked >= 3);
}

/// Structural rejects: wrong-length pk/sig and oversized context fail closed.
fn structuralSuite(comptime P: ml_dsa.Params, vectors_txt: []const u8) !void {
    const a = testing.allocator;
    var vecs = try parseVectors(a, vectors_txt);
    defer {
        for (vecs.items) |v| freeVector(a, v);
        vecs.deinit(a);
    }

    var base: ?Vector = null;
    for (vecs.items) |v| {
        if (v.expect and v.mode == .external) {
            base = v;
            break;
        }
    }
    const v = base orelse return error.NoAcceptVector;

    // Truncated public key / signature must fail closed (no panic, no OOB).
    try testing.expect(!ml_dsa.verify(P, v.pk[0 .. v.pk.len - 1], v.msg, v.ctx, v.sig));
    try testing.expect(!ml_dsa.verify(P, v.pk, v.msg, v.ctx, v.sig[0 .. v.sig.len - 1]));
    try testing.expect(!ml_dsa.verifyInternalFor(P, v.pk, v.msg, v.sig[0 .. v.sig.len - 1]));

    // Over-length context (>255) is rejected without touching the lattice math.
    const big_ctx = try a.alloc(u8, 256);
    defer a.free(big_ctx);
    @memset(big_ctx, 0);
    try testing.expect(!ml_dsa.verify(P, v.pk, v.msg, big_ctx, v.sig));
}

/// Encode one DER TLV (`tag ‖ len ‖ val`) into arena-owned bytes.
fn derTlv(a: std.mem.Allocator, tag: u8, val: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(a, tag);
    if (val.len < 0x80) {
        try out.append(a, @intCast(val.len));
    } else {
        var tmp: [8]u8 = undefined;
        var n = val.len;
        var c: usize = 0;
        while (n != 0) : (n >>= 8) {
            tmp[tmp.len - 1 - c] = @truncate(n);
            c += 1;
        }
        try out.append(a, 0x80 | @as(u8, @intCast(c)));
        try out.appendSlice(a, tmp[tmp.len - c ..]);
    }
    try out.appendSlice(a, val);
    return out.toOwnedSlice(a);
}

/// Wrap a raw ML-DSA public key in a SubjectPublicKeyInfo:
///   SEQUENCE { SEQUENCE { OID }, BIT STRING (0x00 ‖ pk) }.
fn buildMlDsaSpki(a: std.mem.Allocator, oid: []const u8, pk: []const u8) ![]u8 {
    const oid_tlv = try derTlv(a, 0x06, oid);
    const alg = try derTlv(a, 0x30, oid_tlv);
    const bit_val = try a.alloc(u8, pk.len + 1);
    bit_val[0] = 0x00; // unused bits
    @memcpy(bit_val[1..], pk);
    const bit = try derTlv(a, 0x03, bit_val);
    const inner = try std.mem.concat(a, u8, &.{ alg, bit });
    return derTlv(a, 0x30, inner);
}

const ExtractFn = *const fn ([]const u8) x509.Error![]const u8;

/// X.509 dispatch wiring: extraction, exact-OID routing, empty-context injection,
/// and BadSignature/InvalidKey fail-closed for one parameter set.
fn dispatchSuite(
    comptime P: ml_dsa.Params,
    vectors_txt: []const u8,
    sig_oid: []const u8,
    extractFn: ExtractFn,
) !void {
    const backing = testing.allocator;
    var vecs = try parseVectors(backing, vectors_txt);
    defer {
        for (vecs.items) |v| freeVector(backing, v);
        vecs.deinit(backing);
    }

    var chosen: ?Vector = null;
    for (vecs.items) |v| {
        if (v.expect and v.mode == .external) {
            chosen = v;
            break;
        }
    }
    const v = chosen orelse return error.NoAcceptVector;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const spki = try buildMlDsaSpki(a, sig_oid, v.pk);

    // (1) The dispatcher's extractor recovers exactly the public key bytes.
    const extracted = try extractFn(spki);
    try testing.expectEqualSlices(u8, v.pk, extracted);

    // (2) The KAT-verified verifier accepts this vector with its real context —
    //     the same lattice code the dispatch's accept path invokes.
    try testing.expect(ml_dsa.verify(P, v.pk, v.msg, v.ctx, v.sig));

    // (3) Dispatch routes this OID to the ML-DSA arm and injects an EMPTY context.
    if (v.ctx.len == 0) {
        // An empty-context accept IS the X.509 path: the dispatch must ACCEPT.
        try x509_verify.verifyCertSignature(v.msg, v.sig, sig_oid, null, spki);
    } else {
        // Non-empty context: the empty-context dispatch cannot reproduce this
        // signature, so it fails as BadSignature (reached the verifier with an
        // empty context) — decisively NOT UnsupportedSigAlg (unrecognized OID).
        try testing.expectError(
            error.BadSignature,
            x509_verify.verifyCertSignature(v.msg, v.sig, sig_oid, null, spki),
        );
    }

    // (4) A near-miss sig OID does NOT reach the ML-DSA arm: with the ML-DSA SPKI
    //     it falls through to the classical extractPublicKey, which rejects the
    //     PQ OID as UnsupportedKey. That the exact OID yields BadSignature (3)
    //     while a one-byte-off OID yields UnsupportedKey proves the arm is keyed
    //     on the full OID, so (3) truly routed to this parameter set's verifier.
    var other_oid = sig_oid[0..9].*;
    other_oid[8] = 0x2f; // .47 — not any ML-DSA parameter set
    try testing.expectError(
        error.UnsupportedKey,
        x509_verify.verifyCertSignature(v.msg, v.sig, &other_oid, null, spki),
    );

    // (5) A single flipped signature byte is rejected as BadSignature.
    const bad_sig = try a.dupe(u8, v.sig);
    bad_sig[P.ctilde_len + 2] ^= 0x01;
    try testing.expectError(
        error.BadSignature,
        x509_verify.verifyCertSignature(v.msg, bad_sig, sig_oid, null, spki),
    );

    // (6) An SPKI whose declared key length is wrong must fail closed.
    const short_spki = try buildMlDsaSpki(a, sig_oid, v.pk[0 .. v.pk.len - 1]);
    try testing.expectError(
        error.InvalidKey,
        x509_verify.verifyCertSignature(v.msg, v.sig, sig_oid, null, short_spki),
    );
}

// ── ML-DSA-44 ────────────────────────────────────────────────────────────────

test "ML-DSA-44 ACVP sigVer known-answer vectors (accept + reject)" {
    try acvpSuite(ml_dsa.params_44, vectors_44);
}
test "ML-DSA-44 tamper: flipping any accept vector's signature/pk/msg rejects" {
    try tamperSuite(ml_dsa.params_44, vectors_44);
}
test "ML-DSA-44 structural rejects: wrong-length pk/sig and oversized context" {
    try structuralSuite(ml_dsa.params_44, vectors_44);
}
test "ML-DSA-44 x509 dispatch: id-ML-DSA-44 routes to the KAT-verified verifier" {
    try dispatchSuite(ml_dsa.params_44, vectors_44, &oid_44, x509.extractMlDsa44PublicKey);
}

// ── ML-DSA-87 ────────────────────────────────────────────────────────────────

test "ML-DSA-87 ACVP sigVer known-answer vectors (accept + reject)" {
    try acvpSuite(ml_dsa.params_87, vectors_87);
}
test "ML-DSA-87 tamper: flipping any accept vector's signature/pk/msg rejects" {
    try tamperSuite(ml_dsa.params_87, vectors_87);
}
test "ML-DSA-87 structural rejects: wrong-length pk/sig and oversized context" {
    try structuralSuite(ml_dsa.params_87, vectors_87);
}
test "ML-DSA-87 x509 dispatch: id-ML-DSA-87 routes to the KAT-verified verifier" {
    try dispatchSuite(ml_dsa.params_87, vectors_87, &oid_87, x509.extractMlDsa87PublicKey);
}
