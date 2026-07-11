// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic-Ocean coverage for the Helix `.clients` (session-snapshot) capsule
//! adoption path at the CAPSULE-STREAM level — the successor's `adoptInheritedSessions`
//! Pass 2 (server.zig ~16619). "Upgrades are where panics live," so this models that
//! loop and asserts the two invariants the recent hardening added:
//!
//!   1. Every inherited client socket fd is ACCOUNTED FOR — adopted onto a live slot,
//!      or recovered+closed on a clean drop — never leaked. When `session_snapshot.decode`
//!      fails, the fd (which sits past the identity strings, not at the front) is still
//!      recovered via `session_snapshot.peekFd` and closed, mirroring the `.s2s_link` path.
//!   2. A client sealed as `was_secured` that arrives WITHOUT a restored TLS engine is
//!      DROPPED (fd closed), never adopted as plaintext — a secured socket must never
//!      silently fall back to cleartext.
//!
//! This is a TEST-ONLY faithful model of the real Pass 1 (TLS index) + Pass 2 (client
//! adoption): the real loop needs a bound reactor, an inherited memfd arena, and live
//! sockets, none of which belong in a deterministic unit test. The model drives the REAL
//! production decoders — `capsule.decodeStream`, `session_snapshot.decode`, and
//! `session_snapshot.peekFd` (the fd-recovery seam) — and injects faults with `fault_loom`
//! at the model's decode site, standing in for the production decode that has no fault site
//! of its own. The TLS index is modeled as the set of fds whose `.tls_session` capsule
//! decoded (constructing a full `tls_conn.ResumeState` is heavy and orthogonal to the fd /
//! secured-drop seams under test). The fd ledger stands in for the kernel fd table; a
//! non-empty ledger after adoption is exactly an fd leak.

const std = @import("std");

const capsule = @import("capsule.zig");
const session_snapshot = @import("session_snapshot.zig");
const fault_loom = @import("../../substrate/fault_loom.zig");

const Allocator = std.mem.Allocator;
const testing = std.testing;

/// A structurally-valid session snapshot for the client on `fd`. `secured` sets the
/// trailing `was_secured` flag the successor keys its fail-safe drop on.
fn sampleSnap(fd: i32, secured: bool) session_snapshot.Snapshot {
    return .{
        .nick = "user",
        .realname = "User Example",
        .account = "user",
        .real_host = "10.0.0.2",
        .host = "cloak-77.orochi",
        .fd = fd,
        .was_secured = secured,
    };
}

/// Encode a current-schema (v2) `.clients` capsule, exactly as this binary seals a
/// carried client at UPGRADE. Caller owns the returned bytes.
fn v2Capsule(allocator: Allocator, snap: session_snapshot.Snapshot) ![]u8 {
    const blob = try session_snapshot.encode(allocator, snap);
    defer allocator.free(blob);
    var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = blob }};
    return capsule.encode(allocator, capsule.make(.clients, fields[0..]));
}

/// Encode a v1 `.clients` capsule as a PRE-BUMP binary would have sealed it: the
/// session blob is 1 byte shorter (no trailing `was_secured` flag) and the header
/// advertises `version=1, min=1, max=1`. Built by encoding the v2 blob, splicing off
/// the trailing byte, and wrapping in a v1 header the current binary still accepts
/// (`min_supported = 1`). Such a client is necessarily NOT secured (the flag defaults
/// false), which is the historical never-drop behavior.
fn v1Capsule(allocator: Allocator, snap: session_snapshot.Snapshot) ![]u8 {
    const v2_blob = try session_snapshot.encode(allocator, snap);
    defer allocator.free(v2_blob);
    const v1_blob = v2_blob[0 .. v2_blob.len - 1]; // strip trailing was_secured byte

    const d = capsule.descriptor(.clients);
    const v1_header = capsule.Header{
        .schema_id = d.schema_id,
        .kind = .clients,
        .version = 1,
        .min_supported = 1,
        .max_supported = 1,
    };
    var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = v1_blob }};
    return capsule.encode(allocator, .{ .header = v1_header, .fields = fields[0..] });
}

/// A sibling (non-clients) capsule used purely as an "unrelated capsule still adopts"
/// marker to prove the client passes are unaffected by any one client's outcome. A
/// `.channels` capsule with an opaque body suffices (the model never decodes it).
fn siblingCapsule(allocator: Allocator, fill: u8) ![]u8 {
    var body: [8]u8 = @splat(fill);
    var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = &body }};
    return capsule.encode(allocator, capsule.make(.channels, fields[0..]));
}

/// Per-client fault site so a single seeded campaign produces a genuinely MIXED
/// interleaving. Keyed by the client's stable inherited fd, which both `adoptStream`
/// and the arming tests recover via `peekFd`, so their site strings always agree.
fn clientsDecodeSite(buf: []u8, fd: i32) []const u8 {
    return std.fmt.bufPrint(buf, "clients.decode.{d}", .{fd}) catch "clients.decode";
}

const AdoptResult = struct {
    siblings_seen: usize = 0,
    adopted: usize = 0,
    adopted_tls: usize = 0,
    /// Clients dropped because they were sealed secured but had no restored TLS engine.
    secured_dropped: usize = 0,
    /// Clients dropped because their session blob failed to decode.
    decode_dropped: usize = 0,
    fds_recovered: usize = 0,
    /// fds still open after adoption — anything > 0 is an fd LEAK.
    fds_leaked: usize = 0,
};

/// A faithful model of `adoptInheritedSessions` Pass 1 + Pass 2. `tls_fds` is the set of
/// fds whose `.tls_session` capsule decoded (the restored-TLS join). `loom`, when non-null,
/// may fail the model's per-client decode site to force the recovery branch. `open` is the
/// modeled kernel fd table for inherited client sockets; on return every inherited fd must
/// be gone from it.
fn adoptStream(
    allocator: Allocator,
    stream: []const u8,
    tls_fds: []const i32,
    loom: ?*fault_loom.Registry,
    open: *std.AutoHashMapUnmanaged(i32, void),
) !AdoptResult {
    var res = AdoptResult{};

    const caps = try capsule.decodeStream(allocator, stream);
    defer {
        for (caps) |*c| c.deinit(allocator);
        allocator.free(caps);
    }

    // Seed the fd ledger from every carried client (models the inherited sockets whose
    // fds survived execve and now MUST be accounted for).
    for (caps) |c| {
        if (c.header.kind != .clients) continue;
        if (c.fields.len == 0) continue;
        if (session_snapshot.peekFd(c.fields[0].bytes)) |fd| {
            if (fd >= 0) try open.put(allocator, fd, {});
        }
    }

    // Sibling marker pass: unrelated capsules keep being seen regardless of outcomes.
    for (caps) |c| {
        if (c.header.kind != .channels) continue;
        res.siblings_seen += 1;
    }

    // Pass 2 model: client adoption, mirroring server.zig ~16619.
    for (caps) |c| {
        if (c.header.kind != .clients) continue;
        if (c.fields.len == 0) continue;

        const decoded: ?session_snapshot.Snapshot = decode_blk: {
            if (loom) |l| {
                var site_buf: [40]u8 = undefined;
                const cap_fd = session_snapshot.peekFd(c.fields[0].bytes) orelse -1;
                const site = clientsDecodeSite(&site_buf, cap_fd);
                l.maybeFail(site, error{Injected}) catch break :decode_blk null;
            }
            break :decode_blk session_snapshot.decode(c.fields[0].bytes) catch null;
        };

        const snap = decoded orelse {
            // Clean drop on decode failure: recover the fd from the fixed mandatory
            // prefix and close it, so a decode failure never leaks the inherited socket.
            res.decode_dropped += 1;
            if (session_snapshot.peekFd(c.fields[0].bytes)) |fd| {
                if (fd >= 0 and open.remove(fd)) res.fds_recovered += 1;
            }
            continue;
        };
        if (snap.fd < 0) continue;

        var tls_present = false;
        for (tls_fds) |f| {
            if (f == snap.fd) {
                tls_present = true;
                break;
            }
        }

        // Fail-SAFE: secured client with no restored TLS engine is dropped, never
        // adopted as plaintext — close its inherited fd.
        if (snap.was_secured and !tls_present) {
            res.secured_dropped += 1;
            if (open.remove(snap.fd)) res.fds_recovered += 1;
            continue;
        }

        // Adopted: the fd is handed to a live slot (kept open, but ACCOUNTED).
        _ = open.remove(snap.fd);
        res.adopted += 1;
        if (tls_present) res.adopted_tls += 1;
    }

    res.fds_leaked = open.count();
    return res;
}

/// Concatenate owned capsule buffers into one arena-format stream, freeing each.
fn joinCaps(allocator: Allocator, parts: []const []u8) ![]u8 {
    var stream: std.ArrayList(u8) = .empty;
    errdefer stream.deinit(allocator);
    for (parts) |p| {
        try stream.appendSlice(allocator, p);
        allocator.free(p);
    }
    return stream.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "clients capsule adoption recovers fd under injected decode fault (resume DST)" {
    const allocator = testing.allocator;

    var loom: fault_loom.Registry = .{};
    defer loom.deinit(allocator);
    // Force the plaintext client on inherited fd 41 to fail decode. Its fd must be
    // recovered (not leaked), while the other client (fd 40) adopts and the sibling
    // capsule is still seen. The site is keyed by fd, matching `adoptStream`.
    var site_buf: [40]u8 = undefined;
    try loom.arm(allocator, clientsDecodeSite(&site_buf, 41), 1, error.Injected);

    const parts = [_][]u8{
        try v2Capsule(allocator, sampleSnap(40, false)),
        try siblingCapsule(allocator, 0xA1),
        try v2Capsule(allocator, sampleSnap(41, false)),
    };
    const stream = try joinCaps(allocator, parts[0..]);
    defer allocator.free(stream);

    var open: std.AutoHashMapUnmanaged(i32, void) = .empty;
    defer open.deinit(allocator);

    const res = try adoptStream(allocator, stream, &.{}, &loom, &open);
    try testing.expectEqual(@as(usize, 1), res.siblings_seen);
    try testing.expectEqual(@as(usize, 1), res.adopted);
    try testing.expectEqual(@as(usize, 1), res.decode_dropped);
    try testing.expectEqual(@as(usize, 1), res.fds_recovered);
    try testing.expectEqual(@as(usize, 0), res.fds_leaked); // clean abort, no leak
}

test "session_snapshot was_secured client without TLS engine is dropped not adopted-plaintext on upgrade" {
    const allocator = testing.allocator;

    // Three carried clients: (a) secured WITH a restored TLS engine → adopts; (b)
    // secured WITHOUT any TLS engine (its TLS capsule was absent/undecodable) → MUST be
    // dropped, never adopted as plaintext; (c) a plaintext client → adopts. Every fd is
    // accounted for; the secured-but-engineless socket is closed, not leaked.
    const parts = [_][]u8{
        try v2Capsule(allocator, sampleSnap(50, true)), // secured, tls present
        try v2Capsule(allocator, sampleSnap(51, true)), // secured, NO tls → drop
        try v2Capsule(allocator, sampleSnap(52, false)), // plaintext
    };
    const stream = try joinCaps(allocator, parts[0..]);
    defer allocator.free(stream);

    var open: std.AutoHashMapUnmanaged(i32, void) = .empty;
    defer open.deinit(allocator);

    const tls_fds = [_]i32{50}; // only fd 50 has a restored TLS engine
    const res = try adoptStream(allocator, stream, tls_fds[0..], null, &open);

    try testing.expectEqual(@as(usize, 2), res.adopted); // 50 + 52
    try testing.expectEqual(@as(usize, 1), res.adopted_tls); // 50
    try testing.expectEqual(@as(usize, 1), res.secured_dropped); // 51 dropped, not plaintext
    try testing.expectEqual(@as(usize, 1), res.fds_recovered); // 51's fd closed
    try testing.expectEqual(@as(usize, 0), res.fds_leaked);
}

test "clients v1 capsule adopts across upgrade while a v2 secured client co-adopts" {
    const allocator = testing.allocator;

    // A mid-fleet upgrade: a v1 client (pre-bump binary, no was_secured byte → plaintext
    // by definition) rides beside a v2 secured client with its TLS engine. Both adopt via
    // the version-tolerant decode (the whole point of `min_supported = 1`); no fd leaks.
    const parts = [_][]u8{
        try v1Capsule(allocator, sampleSnap(60, false)),
        try siblingCapsule(allocator, 0xC3),
        try v2Capsule(allocator, sampleSnap(61, true)),
    };
    const stream = try joinCaps(allocator, parts[0..]);
    defer allocator.free(stream);

    var open: std.AutoHashMapUnmanaged(i32, void) = .empty;
    defer open.deinit(allocator);

    const tls_fds = [_]i32{61};
    const res = try adoptStream(allocator, stream, tls_fds[0..], null, &open);
    try testing.expectEqual(@as(usize, 1), res.siblings_seen);
    try testing.expectEqual(@as(usize, 2), res.adopted);
    try testing.expectEqual(@as(usize, 0), res.secured_dropped);
    try testing.expectEqual(@as(usize, 0), res.decode_dropped);
    try testing.expectEqual(@as(usize, 0), res.fds_leaked);
}

test "clients capsule adoption seeded fault campaign keeps fd ledger balanced on upgrade" {
    const allocator = testing.allocator;

    // Sweep a spread of seeds. The fault site is keyed per client, so a single seed
    // produces a genuinely MIXED interleaving — some clients drop, others adopt — and
    // under EVERY interleaving the safety invariant must hold: no fd leaks, every dropped
    // client's fd recovered, siblings always seen. On failure the seed is printed to replay.
    const seeds = [_]u64{
        0x0000_0000_0000_0001,
        0xa11c_e5ee_d0d0_beef,
        0xdead_beef_cafe_f00d,
        0x1234_5678_9abc_def0,
        0xffff_ffff_ffff_ffff,
        0x5eed_5eed_5eed_5eed,
    };

    for (seeds) |seed| {
        runCampaign(allocator, seed) catch |e| {
            std.debug.print(
                "clients adopt fault-campaign FAILED — replay with seed=0x{x:0>16}\n",
                .{seed},
            );
            return e;
        };
    }
}

fn runCampaign(allocator: Allocator, seed: u64) !void {
    var loom: fault_loom.Registry = .{};
    defer loom.deinit(allocator);
    loom.setCampaign(.{ .seed = seed, .one_in = 2, .err = error.Injected });

    // Two secured clients (70, 72) both have a restored TLS engine, so an ADOPTED secured
    // client is never mis-dropped; one plaintext client (71). Whatever the campaign fails
    // at decode is recovered; whatever survives adopts. All three fds must be accounted for.
    const parts = [_][]u8{
        try siblingCapsule(allocator, 0xE5),
        try v2Capsule(allocator, sampleSnap(70, true)),
        try v2Capsule(allocator, sampleSnap(71, false)),
        try v2Capsule(allocator, sampleSnap(72, true)),
        try siblingCapsule(allocator, 0xF6),
    };
    const stream = try joinCaps(allocator, parts[0..]);
    defer allocator.free(stream);

    var open: std.AutoHashMapUnmanaged(i32, void) = .empty;
    defer open.deinit(allocator);

    const tls_fds = [_]i32{ 70, 72 };
    const res = try adoptStream(allocator, stream, tls_fds[0..], &loom, &open);

    try testing.expectEqual(@as(usize, 2), res.siblings_seen);
    // Every client is either adopted or decode-dropped (no secured-drop: both secured
    // clients have their TLS engine present).
    try testing.expectEqual(@as(usize, 3), res.adopted + res.decode_dropped);
    try testing.expectEqual(@as(usize, 0), res.secured_dropped);
    try testing.expectEqual(res.decode_dropped, res.fds_recovered); // every drop recovered
    try testing.expectEqual(@as(usize, 0), res.fds_leaked); // never leak an fd
}
