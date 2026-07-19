// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Independent known-answer tests for SLH-DSA (FIPS 205) signature verification,
//! covering ALL 12 standardized parameter sets (SHA2 and SHAKE, {128,192,256}×
//! {s,f}).
//!
//! The vectors embedded here are NIST ACVP FIPS 205 `SLH-DSA-sigVer` test cases
//! taken verbatim from `usnistgov/ACVP-Server:gen-val/json-files/
//! SLH-DSA-sigVer-FIPS205/internalProjection.json`, plus one empty-context accept
//! per hash-family representative sourced from the matching `SLH-DSA-sigGen`
//! corpus (the X.509 certificate path uses an empty context, which most sigVer
//! accept cases in this lean corpus do not). All are INDEPENDENT published
//! vectors — triples of (public key, message, signature) with a NIST-supplied
//! accept/reject verdict — NOT values this code produced (Onyx Server has no SLH-DSA
//! signer or key generator). That independence is the whole point: a
//! plausible-but-wrong hash-based verifier passes the module's own
//! self-consistency checks but fails these ACVP accept vectors.
//!
//! Interfaces exercised per set:
//!   * external / pure  → `verify(pk, msg, ctx, sig)` (0x00‖len(ctx)‖ctx prefix).
//!   * internal         → `verifyInternal(pk, M′, sig)`.
//! Stored rejects are real ACVP "modified message" / "modified signature"
//! verdicts; broad bit-flip tamper coverage is generated dynamically below.

const std = @import("std");
const slh_dsa = @import("slh_dsa.zig");
const x509_verify = @import("x509_verify.zig");
const testing = std.testing;

const vectors_txt = @embedFile("slh_dsa_sigver_acvp.txt");

const Mode = enum { external, internal };

const Vector = struct {
    set: []const u8,
    mode: Mode,
    expect: bool,
    tc: []const u8,
    reason: []const u8,
    pk: []u8,
    ctx: []u8,
    msg: []u8,
    sig: []u8,
};

/// Every standardized parameter set, paired with its ACVP name, X.509 OID suffix
/// byte (id-slh-dsa-* = 2.16.840.1.101.3.4.3.{20..31}), and raw public-key length.
const Spec = struct {
    name: []const u8,
    Verifier: type,
    oid_suffix: u8,
    pk_len: usize,
};

const specs = [_]Spec{
    .{ .name = "SLH-DSA-SHA2-128s", .Verifier = slh_dsa.Sha2_128s, .oid_suffix = 0x14, .pk_len = 32 },
    .{ .name = "SLH-DSA-SHA2-128f", .Verifier = slh_dsa.Sha2_128f, .oid_suffix = 0x15, .pk_len = 32 },
    .{ .name = "SLH-DSA-SHA2-192s", .Verifier = slh_dsa.Sha2_192s, .oid_suffix = 0x16, .pk_len = 48 },
    .{ .name = "SLH-DSA-SHA2-192f", .Verifier = slh_dsa.Sha2_192f, .oid_suffix = 0x17, .pk_len = 48 },
    .{ .name = "SLH-DSA-SHA2-256s", .Verifier = slh_dsa.Sha2_256s, .oid_suffix = 0x18, .pk_len = 64 },
    .{ .name = "SLH-DSA-SHA2-256f", .Verifier = slh_dsa.Sha2_256f, .oid_suffix = 0x19, .pk_len = 64 },
    .{ .name = "SLH-DSA-SHAKE-128s", .Verifier = slh_dsa.Shake_128s, .oid_suffix = 0x1A, .pk_len = 32 },
    .{ .name = "SLH-DSA-SHAKE-128f", .Verifier = slh_dsa.Shake_128f, .oid_suffix = 0x1B, .pk_len = 32 },
    .{ .name = "SLH-DSA-SHAKE-192s", .Verifier = slh_dsa.Shake_192s, .oid_suffix = 0x1C, .pk_len = 48 },
    .{ .name = "SLH-DSA-SHAKE-192f", .Verifier = slh_dsa.Shake_192f, .oid_suffix = 0x1D, .pk_len = 48 },
    .{ .name = "SLH-DSA-SHAKE-256s", .Verifier = slh_dsa.Shake_256s, .oid_suffix = 0x1E, .pk_len = 64 },
    .{ .name = "SLH-DSA-SHAKE-256f", .Verifier = slh_dsa.Shake_256f, .oid_suffix = 0x1F, .pk_len = 64 },
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
                .set = "",
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
        if (std.mem.eql(u8, key, "set")) {
            cur.set = val;
        } else if (std.mem.eql(u8, key, "mode")) {
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

/// Dispatch a vector to its parameter set's verifier. Returns null for an
/// unrecognized set name (which the caller treats as a test failure).
fn runVector(v: Vector) ?bool {
    inline for (specs) |s| {
        if (std.mem.eql(u8, v.set, s.name)) {
            return switch (v.mode) {
                .external => s.Verifier.verify(v.pk, v.msg, v.ctx, v.sig),
                .internal => s.Verifier.verifyInternal(v.pk, v.msg, v.sig),
            };
        }
    }
    return null;
}

test "SLH-DSA ACVP sigVer known-answer vectors, all 12 parameter sets (accept + reject)" {
    const a = testing.allocator;
    var vecs = try parseVectors(a);
    defer {
        for (vecs.items) |v| freeVector(a, v);
        vecs.deinit(a);
    }

    // Sanity: we loaded the expected corpus (>= 4 records per set), not a stub.
    try testing.expect(vecs.items.len >= 48);

    // Track which sets produced an accept, so "all pass" cannot be vacuous for
    // any single set (e.g. an unrecognized name silently skipped).
    var accept_by_set: [specs.len]bool = @splat(false);
    var accept_seen: usize = 0;
    var reject_seen: usize = 0;
    for (vecs.items) |v| {
        const got = runVector(v) orelse {
            std.debug.print("SLH-DSA KAT: unrecognized set '{s}'\n", .{v.set});
            return error.UnknownSet;
        };
        if (got != v.expect) {
            std.debug.print(
                "SLH-DSA KAT MISMATCH: set={s} mode={s} tc={s} expected={} got={} reason={s}\n",
                .{ v.set, @tagName(v.mode), v.tc, v.expect, got, v.reason },
            );
            return error.KatMismatch;
        }
        if (v.expect) {
            accept_seen += 1;
            inline for (specs, 0..) |s, i| {
                if (std.mem.eql(u8, v.set, s.name)) accept_by_set[i] = true;
            }
        } else {
            reject_seen += 1;
        }
    }

    // Every set must have at least one *passing* accept vector — the real proof
    // that its full tree walk / ADRS / hash family is correct.
    inline for (specs, 0..) |s, i| {
        if (!accept_by_set[i]) {
            std.debug.print("SLH-DSA KAT: no accept vector verified for {s}\n", .{s.name});
            return error.MissingAcceptForSet;
        }
    }
    try testing.expect(accept_seen >= specs.len);
    try testing.expect(reject_seen >= specs.len);
}

test "SLH-DSA tamper: flipping any accept vector's signature/pk/msg rejects" {
    const a = testing.allocator;
    var vecs = try parseVectors(a);
    defer {
        for (vecs.items) |v| freeVector(a, v);
        vecs.deinit(a);
    }

    var checked: usize = 0;
    for (vecs.items) |v| {
        if (!v.expect) continue; // start from a known-good triple
        try testing.expect(runVector(v).?);

        // Flip one bit deep in the signature body (in the SIG_HT region).
        {
            const dup = try a.dupe(u8, v.sig);
            defer a.free(dup);
            dup[dup.len - 100] ^= 0x01;
            var w = v;
            w.sig = dup;
            try testing.expect(!runVector(w).?);
        }
        // Flip one bit of the public key (PK.root half).
        {
            const dup = try a.dupe(u8, v.pk);
            defer a.free(dup);
            dup[dup.len - 1] ^= 0x80;
            var w = v;
            w.pk = dup;
            try testing.expect(!runVector(w).?);
        }
        // Flip one bit of the message (if non-empty).
        if (v.msg.len > 0) {
            const dup = try a.dupe(u8, v.msg);
            defer a.free(dup);
            dup[0] ^= 0x01;
            var w = v;
            w.msg = dup;
            try testing.expect(!runVector(w).?);
        }
        checked += 1;
    }
    try testing.expect(checked >= specs.len);
}

test "SLH-DSA structural rejects: wrong-length pk/sig and oversized context" {
    const a = testing.allocator;
    var vecs = try parseVectors(a);
    defer {
        for (vecs.items) |v| freeVector(a, v);
        vecs.deinit(a);
    }

    var checked: usize = 0;
    for (vecs.items) |v| {
        if (!(v.expect and v.mode == .external)) continue;
        // Truncated pk / sig must fail closed (no panic, no OOB) for this set.
        var t = v;
        t.pk = v.pk[0 .. v.pk.len - 1];
        try testing.expect(!(runVector(t) orelse return error.UnknownSet));
        t = v;
        t.sig = v.sig[0 .. v.sig.len - 1];
        try testing.expect(!(runVector(t) orelse return error.UnknownSet));
        // Over-length context (>255) is rejected without touching the hash trees.
        const big_ctx = try a.alloc(u8, 256);
        defer a.free(big_ctx);
        @memset(big_ctx, 0);
        t = v;
        t.ctx = big_ctx;
        try testing.expect(!(runVector(t) orelse return error.UnknownSet));
        checked += 1;
    }
    try testing.expect(checked >= specs.len);
}

// ── X.509 dispatch wiring ───────────────────────────────────────────────────

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

/// Wrap a raw SLH-DSA public key in a SubjectPublicKeyInfo:
///   SEQUENCE { SEQUENCE { OID id-slh-dsa-* }, BIT STRING (0x00 ‖ pk) }.
fn buildSlhDsaSpki(a: std.mem.Allocator, oid_suffix: u8, pk: []const u8) ![]u8 {
    const oid = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, oid_suffix };
    const oid_tlv = try derTlv(a, 0x06, &oid);
    const alg = try derTlv(a, 0x30, oid_tlv);
    const bit_val = try a.alloc(u8, pk.len + 1);
    bit_val[0] = 0x00; // unused bits
    @memcpy(bit_val[1..], pk);
    const bit = try derTlv(a, 0x03, bit_val);
    const inner = try std.mem.concat(a, u8, &.{ alg, bit });
    return derTlv(a, 0x30, inner);
}

test "x509 dispatch: verifyCertSignature routes id-slh-dsa-* (empty-context cert path)" {
    const backing = testing.allocator;
    var vecs = try parseVectors(backing);
    defer {
        for (vecs.items) |v| freeVector(backing, v);
        vecs.deinit(backing);
    }

    // The empty-context external accept vectors (sigGen-sourced, one per hash
    // family) are exactly the X.509 path: verifyCertSignature verifies with an
    // empty SLH-DSA context. Prove full accept + tamper-reject + wrong-key
    // through the real dispatcher for each hash family represented.
    var checked: usize = 0;
    for (vecs.items) |v| {
        if (!(v.expect and v.mode == .external and v.ctx.len == 0)) continue;

        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var handled = false;
        inline for (specs) |s| {
            if (std.mem.eql(u8, v.set, s.name)) {
                handled = true;
                const sig_alg_oid = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, s.oid_suffix };
                const spki = try buildSlhDsaSpki(a, s.oid_suffix, v.pk);

                // Treat the vector's message as the TBSCertificate bytes; the
                // dispatcher verifies the correct SLH-DSA set with empty context.
                try x509_verify.verifyCertSignature(v.msg, v.sig, &sig_alg_oid, null, spki);

                // A single flipped signature byte must be rejected as BadSignature.
                const bad_sig = try a.dupe(u8, v.sig);
                bad_sig[bad_sig.len - 50] ^= 0x01;
                try testing.expectError(
                    error.BadSignature,
                    x509_verify.verifyCertSignature(v.msg, bad_sig, &sig_alg_oid, null, spki),
                );

                // An SPKI whose declared key length is wrong must fail closed.
                const short_spki = try buildSlhDsaSpki(a, s.oid_suffix, v.pk[0 .. v.pk.len - 1]);
                try testing.expectError(
                    error.InvalidKey,
                    x509_verify.verifyCertSignature(v.msg, v.sig, &sig_alg_oid, null, short_spki),
                );
                checked += 1;
            }
        }
        if (!handled) return error.UnknownSet;
    }
    // One per hash family: SHA2 cat1, SHA2 cat3/5, SHAKE.
    try testing.expect(checked >= 3);
}
