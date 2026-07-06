// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Independent known-answer tests for SLH-DSA-SHA2-128s (FIPS 205) signature
//! verification.
//!
//! The vectors embedded here are NIST ACVP FIPS 205 `SLH-DSA-sigVer` test cases
//! (parameter set SLH-DSA-SHA2-128s) taken verbatim from
//! `usnistgov/ACVP-Server:gen-val/json-files/SLH-DSA-sigVer-FIPS205/
//! internalProjection.json`, plus one empty-context accept case sourced from the
//! matching `SLH-DSA-sigGen-FIPS205` corpus (the X.509 certificate path uses an
//! empty context, and the sigVer accept cases all carry non-empty contexts). All
//! are INDEPENDENT published vectors — triples of (public key, message, signature)
//! with a NIST-supplied accept/reject verdict — NOT values this code produced.
//! That independence is the whole point: a plausible-but-wrong hash-based
//! verifier passes the module's own self-consistency checks but fails these ACVP
//! accept vectors.
//!
//! Two interfaces are covered:
//!   * external / pure  (ACVP sigVer tgId 19) → `verify(pk, msg, ctx, sig)`,
//!     exercising the 0x00‖len(ctx)‖ctx domain prefix, plus the empty-context
//!     sigGen accept (the X.509 path).
//!   * internal         (ACVP sigVer tgId 31) → `verifyInternal(pk, M′, sig)`.
//!
//! Reject cases span every ACVP failure class: modified message, modified R,
//! modified FORS signature, modified hypertree signature, and structural
//! wrong-length (too small / too large).

const std = @import("std");
const slh_dsa = @import("slh_dsa.zig");
const x509_verify = @import("x509_verify.zig");
const testing = std.testing;

const vectors_txt = @embedFile("slh_dsa_sha2_128s_sigver_acvp.txt");

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
fn parseVectors(a: std.mem.Allocator) !std.ArrayList(Vector) {
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

fn runVector(v: Vector) bool {
    return switch (v.mode) {
        .external => slh_dsa.verify(v.pk, v.msg, v.ctx, v.sig),
        .internal => slh_dsa.verifyInternal(v.pk, v.msg, v.sig),
    };
}

test "SLH-DSA-SHA2-128s ACVP sigVer known-answer vectors (accept + reject)" {
    const a = testing.allocator;
    var vecs = try parseVectors(a);
    defer {
        for (vecs.items) |v| freeVector(a, v);
        vecs.deinit(a);
    }

    // Sanity: we actually loaded the expected corpus, not an empty file.
    try testing.expect(vecs.items.len >= 28);

    var accept_seen: usize = 0;
    var reject_seen: usize = 0;
    for (vecs.items) |v| {
        const got = runVector(v);
        if (got != v.expect) {
            std.debug.print(
                "SLH-DSA-SHA2-128s KAT MISMATCH: mode={s} tc={s} expected={} got={} reason={s}\n",
                .{ @tagName(v.mode), v.tc, v.expect, got, v.reason },
            );
            return error.KatMismatch;
        }
        if (v.expect) accept_seen += 1 else reject_seen += 1;
    }

    // The corpus must contain both verdicts, or "all pass" would be vacuous.
    try testing.expect(accept_seen >= 3);
    try testing.expect(reject_seen >= 3);
}

test "SLH-DSA-SHA2-128s tamper: flipping any accept vector's signature/pk/msg rejects" {
    const a = testing.allocator;
    var vecs = try parseVectors(a);
    defer {
        for (vecs.items) |v| freeVector(a, v);
        vecs.deinit(a);
    }

    var checked: usize = 0;
    for (vecs.items) |v| {
        if (!v.expect) continue; // start from a known-good triple

        // Baseline must still verify.
        try testing.expect(runVector(v));

        // Flip one bit deep in the signature body (in the SIG_HT region, past R
        // and the FORS signature).
        {
            const dup = try a.dupe(u8, v.sig);
            defer a.free(dup);
            dup[dup.len - 100] ^= 0x01;
            var w = v;
            w.sig = dup;
            try testing.expect(!runVector(w));
        }
        // Flip one bit of the public key (PK.root half).
        {
            const dup = try a.dupe(u8, v.pk);
            defer a.free(dup);
            dup[dup.len - 1] ^= 0x80;
            var w = v;
            w.pk = dup;
            try testing.expect(!runVector(w));
        }
        // Flip one bit of the message (if non-empty).
        if (v.msg.len > 0) {
            const dup = try a.dupe(u8, v.msg);
            defer a.free(dup);
            dup[0] ^= 0x01;
            var w = v;
            w.msg = dup;
            try testing.expect(!runVector(w));
        }
        checked += 1;
    }
    try testing.expect(checked >= 3);
}

test "SLH-DSA-SHA2-128s structural rejects: wrong-length pk/sig and oversized context" {
    const a = testing.allocator;
    var vecs = try parseVectors(a);
    defer {
        for (vecs.items) |v| freeVector(a, v);
        vecs.deinit(a);
    }

    // Use the first external accept vector as a valid base.
    var base: ?Vector = null;
    for (vecs.items) |v| {
        if (v.expect and v.mode == .external) {
            base = v;
            break;
        }
    }
    const v = base orelse return error.NoAcceptVector;

    // Truncated public key / signature must fail closed (no panic, no OOB).
    try testing.expect(!slh_dsa.verify(v.pk[0 .. v.pk.len - 1], v.msg, v.ctx, v.sig));
    try testing.expect(!slh_dsa.verify(v.pk, v.msg, v.ctx, v.sig[0 .. v.sig.len - 1]));
    try testing.expect(!slh_dsa.verifyInternal(v.pk, v.msg, v.sig[0 .. v.sig.len - 1]));

    // Over-length context (>255) is rejected without touching the hash trees.
    const big_ctx = try a.alloc(u8, 256);
    defer a.free(big_ctx);
    @memset(big_ctx, 0);
    try testing.expect(!slh_dsa.verify(v.pk, v.msg, big_ctx, v.sig));
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

/// Wrap a raw SLH-DSA-SHA2-128s public key in a SubjectPublicKeyInfo:
///   SEQUENCE { SEQUENCE { OID id-slh-dsa-sha2-128s }, BIT STRING (0x00 ‖ pk) }.
fn buildSlhDsaSpki(a: std.mem.Allocator, pk: []const u8) ![]u8 {
    const oid = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14 };
    const oid_tlv = try derTlv(a, 0x06, &oid);
    const alg = try derTlv(a, 0x30, oid_tlv);
    const bit_val = try a.alloc(u8, pk.len + 1);
    bit_val[0] = 0x00; // unused bits
    @memcpy(bit_val[1..], pk);
    const bit = try derTlv(a, 0x03, bit_val);
    const inner = try std.mem.concat(a, u8, &.{ alg, bit });
    return derTlv(a, 0x30, inner);
}

test "x509 dispatch: verifyCertSignature routes id-slh-dsa-sha2-128s to the KAT-verified verifier" {
    // id-slh-dsa-sha2-128s in the outer signatureAlgorithm (2.16.840.1.101.3.4.3.20).
    const sig_alg_oid = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14 };

    const backing = testing.allocator;
    var vecs = try parseVectors(backing);
    defer {
        for (vecs.items) |v| freeVector(backing, v);
        vecs.deinit(backing);
    }

    // The empty-context external accept vector is exactly the X.509 path:
    // verifyCertSignature verifies with an empty SLH-DSA context.
    var chosen: ?Vector = null;
    for (vecs.items) |v| {
        if (v.expect and v.mode == .external and v.ctx.len == 0) {
            chosen = v;
            break;
        }
    }
    const v = chosen orelse return error.NoEmptyContextAcceptVector;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const spki = try buildSlhDsaSpki(a, v.pk);

    // Treat the vector's message as the TBSCertificate bytes; the dispatcher
    // verifies SLH-DSA-SHA2-128s over them with an empty context.
    try x509_verify.verifyCertSignature(v.msg, v.sig, &sig_alg_oid, null, spki);

    // A single flipped signature byte must be rejected as BadSignature.
    const bad_sig = try a.dupe(u8, v.sig);
    bad_sig[bad_sig.len - 50] ^= 0x01;
    try testing.expectError(
        error.BadSignature,
        x509_verify.verifyCertSignature(v.msg, bad_sig, &sig_alg_oid, null, spki),
    );

    // An SPKI whose declared key length is wrong must fail closed.
    const short_spki = try buildSlhDsaSpki(a, v.pk[0 .. v.pk.len - 1]);
    try testing.expectError(
        error.InvalidKey,
        x509_verify.verifyCertSignature(v.msg, v.sig, &sig_alg_oid, null, short_spki),
    );
}
