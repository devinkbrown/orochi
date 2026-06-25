// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic self-test harness for the FULL Helix upgrade MULTI-SESSION /
//! bouncer-state round-trip, exercised entirely in-process WITHOUT the real
//! server.
//!
//! Where `upgrade_dst.zig` proves that a single live connection's `ConnCapsule`
//! plus its descriptor survive the handoff, this file proves that the
//! ACCOUNT-level session registry — the durable set of attached and detached
//! (bouncer) sessions per account — survives the same SEQPACKET conduit
//! crossing. The flow is:
//!
//!   1. Encode several per-account `SessionCapsule`s into one framed payload.
//!   2. `conduit.send` it from a sender thread on one socket end while
//!      `conduit.recv` reads it on the other. The conduit splits the payload
//!      across its fd batches and so requires at least one descriptor to carry a
//!      non-empty payload; a single throwaway carrier fd is attached purely as a
//!      vehicle and closed on receipt. No client descriptors are involved — the
//!      session registry is pure state.
//!   3. Decode each capsule on the "successor" side into owned buffers, since
//!      the conduit payload is freed before this function returns.
//!   4. Run the session resume planner against the migrated live-client id set
//!      to classify every session as attached or detached.
//!
//! No daemon internals are touched: a socket pair and a sender thread stand in
//! for the execve'd successor.
//!
//! Multi-capsule payload framing (all integers big-endian):
//!
//!   count : u32                       number of capsules in the blob
//!   then `count` records, each:
//!     len    : u32                    byte length of the encoded capsule
//!     capsule: len bytes              `SessionCapsule.encode` output
//!
//! The `count` prefix lets the receiver pre-size its decode loop; the per-record
//! `len` prefix lets it slice each capsule exactly without re-parsing the codec's
//! internal layout.

const std = @import("std");
const builtin = @import("builtin");

const session_capsule = @import("session_capsule.zig");
const session_resume_plan = @import("session_resume_plan.zig");
const conduit = @import("conduit.zig");
const handoff = @import("handoff.zig");

const Allocator = std.mem.Allocator;

/// Width of the count prefix and of each per-capsule length prefix.
const count_prefix_len: usize = 4;
const record_len_prefix: usize = 4;

pub const Error = conduit.Error || session_capsule.Error ||
    session_resume_plan.Error || std.Thread.SpawnError || error{
    /// The received payload was malformed or its count did not match.
    Protocol,
    /// A carrier descriptor could not be opened for the conduit transfer.
    CarrierUnavailable,
};

/// Summary tallies of a full session-migration round-trip.
pub const Outcome = struct {
    /// Total sessions decoded across all capsules on the successor side.
    recovered: usize,
    /// Sessions whose client id appeared in the migrated live-client set.
    attached: usize,
    /// Sessions whose connection did not survive (replay buffer needed).
    detached: usize,
};

/// One account's decoded session capsule with allocator-owned backing for every
/// string slice (account + each token) and for the `SessionEntry` array.
///
/// `SessionCapsule.decode` borrows account/token strings from the input bytes
/// and the `SessionEntry` array from a caller-supplied buffer; both the transient
/// conduit payload and any stack buffer would be gone before the planner runs, so
/// this copies everything into heap-owned storage and re-points the slices at it.
const OwnedCapsule = struct {
    capsule: session_capsule.SessionCapsule,
    entries: []session_capsule.SessionEntry,
    strings: []u8,

    fn deinit(self: *OwnedCapsule, allocator: Allocator) void {
        allocator.free(self.entries);
        allocator.free(self.strings);
        self.* = undefined;
    }
};

/// Encode `capsules` into a single framed payload buffer (see file header for
/// the layout). Caller frees the returned slice.
fn buildPayload(
    allocator: Allocator,
    capsules: []const session_capsule.SessionCapsule,
) Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    var count_prefix: [count_prefix_len]u8 = undefined;
    std.mem.writeInt(u32, &count_prefix, @intCast(capsules.len), .big);
    try buf.appendSlice(allocator, &count_prefix);

    // Scratch large enough for any single session capsule we expect to encode.
    var scratch: [8192]u8 = undefined;
    for (capsules) |c| {
        const wire = try c.encode(&scratch);
        var len_prefix: [record_len_prefix]u8 = undefined;
        std.mem.writeInt(u32, &len_prefix, @intCast(wire.len), .big);
        try buf.appendSlice(allocator, &len_prefix);
        try buf.appendSlice(allocator, wire);
    }

    return buf.toOwnedSlice(allocator);
}

/// Decode one capsule from `record` into heap-owned storage. The codec hands
/// back account/token slices borrowing `record` and an entry array borrowing a
/// scratch buffer; both are copied here so the returned `OwnedCapsule` outlives
/// the conduit payload. Caller frees via `OwnedCapsule.deinit`.
fn decodeOwned(allocator: Allocator, record: []const u8) Error!OwnedCapsule {
    // First decode into scratch entries so we learn the session count and can
    // size the heap copies exactly. A capsule cannot encode more sessions than
    // fit a u16, but realistic counts are tiny; cap the scratch conservatively.
    var scratch_entries: [4096]session_capsule.SessionEntry = undefined;
    const view = try session_capsule.SessionCapsule.decode(record, &scratch_entries);

    // Total string bytes = account + every token.
    var string_total: usize = view.account.len;
    for (view.sessions) |e| string_total += e.token.len;

    const strings = try allocator.alloc(u8, string_total);
    errdefer allocator.free(strings);
    const entries = try allocator.alloc(session_capsule.SessionEntry, view.sessions.len);
    errdefer allocator.free(entries);

    var off: usize = 0;
    const take = struct {
        fn f(dst: []u8, o: *usize, src: []const u8) []const u8 {
            @memcpy(dst[o.* .. o.* + src.len], src);
            const slice = dst[o.* .. o.* + src.len];
            o.* += src.len;
            return slice;
        }
    }.f;

    const account = take(strings, &off, view.account);
    for (view.sessions, 0..) |e, i| {
        entries[i] = .{
            .token = take(strings, &off, e.token),
            .signon_unix = e.signon_unix,
            .detached = e.detached,
            .client = e.client,
        };
    }

    return .{
        .capsule = .{ .account = account, .sessions = entries },
        .entries = entries,
        .strings = strings,
    };
}

/// Decode the framed payload into `out`, returning the number of capsules.
/// Caller frees each entry via `OwnedCapsule.deinit`.
fn decodePayload(
    allocator: Allocator,
    payload: []const u8,
    out: []OwnedCapsule,
) Error!usize {
    if (payload.len < count_prefix_len) return error.Protocol;
    const count = std.mem.readInt(u32, payload[0..count_prefix_len], .big);
    if (count > out.len) return error.Protocol;

    var pos: usize = count_prefix_len;
    var i: usize = 0;
    errdefer for (out[0..i]) |*c| c.deinit(allocator);
    while (i < count) : (i += 1) {
        if (pos + record_len_prefix > payload.len) return error.Protocol;
        const rec_len = std.mem.readInt(u32, payload[pos..][0..record_len_prefix], .big);
        pos += record_len_prefix;
        if (pos + rec_len > payload.len) return error.Protocol;

        out[i] = try decodeOwned(allocator, payload[pos .. pos + rec_len]);
        pos += rec_len;
    }

    if (pos != payload.len) return error.Protocol;
    return count;
}

/// Context for the sender thread. SEQPACKET sends can block until the peer
/// reads, so the send half runs on its own thread while the caller receives.
const SendCtx = struct {
    sock: handoff.Fd,
    fds: []const handoff.Fd,
    payload: []const u8,
    result: conduit.Error!void = undefined,

    fn run(self: *SendCtx) void {
        self.result = conduit.send(self.sock, self.fds, self.payload);
    }
};

/// Open a single throwaway descriptor to act as the conduit's payload carrier.
/// The conduit refuses a non-empty payload with zero fds (it slices the payload
/// across its fd batches), so a session-registry transfer — which carries no
/// client sockets of its own — still needs one vehicle fd. Returns a dup of a
/// fresh pipe read end. Caller closes the returned fd.
fn openCarrierFd() error{SkipZigTest}!handoff.Fd {
    var pipe_fds: [2]i32 = undefined;
    {
        const rc = std.os.linux.pipe(&pipe_fds);
        if (std.os.linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    }
    defer {
        _ = std.os.linux.close(pipe_fds[0]);
        _ = std.os.linux.close(pipe_fds[1]);
    }
    const rc = std.os.linux.dup(pipe_fds[0]);
    if (std.os.linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    return @intCast(rc);
}

/// Run the full encode -> conduit.send -> conduit.recv -> decode -> resume-plan
/// round-trip over a fresh socket pair and return the attach/detach tallies.
///
/// Every session across every capsule is recovered on the successor side and
/// classified: a session is ATTACHED iff its client id appears in
/// `live_client_ids` (the connections that successfully migrated), else DETACHED.
/// All transient and owned buffers are freed before returning; the caller keeps
/// only the returned tallies.
pub fn roundTrip(
    allocator: Allocator,
    capsules: []const session_capsule.SessionCapsule,
    live_client_ids: []const u64,
) Error!Outcome {
    if (builtin.os.tag != .linux) return error.Unsupported;

    const payload = try buildPayload(allocator, capsules);
    defer allocator.free(payload);

    var sockets = try handoff.socketPair();
    defer sockets.close();

    // One throwaway descriptor carries the payload across the conduit (which
    // cannot ship a non-empty payload with zero fds). It models no client.
    const carrier = openCarrierFd() catch return error.CarrierUnavailable;
    defer _ = std.os.linux.close(carrier);
    const carrier_fds = [_]handoff.Fd{carrier};

    var ctx = SendCtx{ .sock = sockets.supervisor, .fds = &carrier_fds, .payload = payload };
    const thread = try std.Thread.spawn(.{}, SendCtx.run, .{&ctx});

    var received = conduit.recv(allocator, sockets.worker) catch |err| {
        thread.join();
        return err;
    };
    defer received.deinit(allocator);

    thread.join();
    try ctx.result;

    // Close the received copy of the carrier; the registry transfer owns no
    // descriptors of its own.
    for (received.fds) |fd| _ = std.os.linux.close(fd);

    // Decode every capsule into heap-owned storage so its slices outlive the
    // payload buffer that `received.deinit` frees above.
    const owned = try allocator.alloc(OwnedCapsule, capsules.len);
    defer allocator.free(owned);
    const decoded_count = try decodePayload(allocator, received.payload, owned);
    defer for (owned[0..decoded_count]) |*c| c.deinit(allocator);

    // Flatten the decoded owned capsules into a contiguous slice for the planner.
    var capsule_views = try allocator.alloc(session_capsule.SessionCapsule, decoded_count);
    defer allocator.free(capsule_views);
    var total_sessions: usize = 0;
    for (owned[0..decoded_count], 0..) |c, i| {
        capsule_views[i] = c.capsule;
        total_sessions += c.capsule.sessions.len;
    }

    const states = try allocator.alloc(session_resume_plan.SessionState, total_sessions);
    defer allocator.free(states);
    const plan = try session_resume_plan.plan(capsule_views, live_client_ids, states);

    return .{
        .recovered = plan.len,
        .attached = session_resume_plan.countAttached(plan),
        .detached = session_resume_plan.countDetached(plan),
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const SessionEntry = session_capsule.SessionEntry;
const SessionCapsule = session_capsule.SessionCapsule;

test "session migration round-trip recovers every session and splits attach/detach by live client set" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    // Account "alice": 3 sessions (clients 10, 20, 30).
    const alice_sessions = [_]SessionEntry{
        .{ .token = "alice-tok-attached-1", .signon_unix = 1_700_000_001, .detached = false, .client = 10 },
        .{ .token = "alice-tok-detached-2", .signon_unix = 1_700_000_002, .detached = true, .client = 20 },
        .{ .token = "alice-tok-attached-3", .signon_unix = 1_700_000_003, .detached = false, .client = 30 },
    };
    // Account "bob": 2 sessions (clients 40, 50).
    const bob_sessions = [_]SessionEntry{
        .{ .token = "bob-tok-detached-1", .signon_unix = 1_700_000_004, .detached = true, .client = 40 },
        .{ .token = "bob-tok-attached-2", .signon_unix = 1_700_000_005, .detached = false, .client = 50 },
    };

    const capsules = [_]SessionCapsule{
        .{ .account = "alice", .sessions = &alice_sessions },
        .{ .account = "bob", .sessions = &bob_sessions },
    };

    const total_sessions = alice_sessions.len + bob_sessions.len; // 5

    // Clients 10, 30, 50 survived the migration; 20 and 40 did not.
    const live = [_]u64{ 10, 30, 50 };

    const outcome = try roundTrip(allocator, &capsules, &live);

    try std.testing.expectEqual(@as(usize, total_sessions), outcome.recovered);
    try std.testing.expectEqual(@as(usize, 3), outcome.attached);
    try std.testing.expectEqual(@as(usize, 2), outcome.detached);
    try std.testing.expectEqual(total_sessions, outcome.attached + outcome.detached);
}

test "session migration round-trip with empty live set detaches every recovered session" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const sessions = [_]SessionEntry{
        .{ .token = "tok-a", .signon_unix = 1, .detached = true, .client = 1 },
        .{ .token = "tok-b", .signon_unix = 2, .detached = true, .client = 2 },
        .{ .token = "tok-c", .signon_unix = 3, .detached = true, .client = 3 },
    };
    const capsules = [_]SessionCapsule{
        .{ .account = "ghost", .sessions = &sessions },
    };

    const live = [_]u64{}; // nothing migrated

    const outcome = try roundTrip(allocator, &capsules, &live);

    try std.testing.expectEqual(@as(usize, 3), outcome.recovered);
    try std.testing.expectEqual(@as(usize, 0), outcome.attached);
    try std.testing.expectEqual(@as(usize, 3), outcome.detached);
}

test "session migration round-trip with all clients live attaches everything" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const a_sessions = [_]SessionEntry{
        .{ .token = "a1", .signon_unix = 100, .detached = false, .client = 7 },
        .{ .token = "a2", .signon_unix = 101, .detached = true, .client = 8 },
    };
    const b_sessions = [_]SessionEntry{
        .{ .token = "b1", .signon_unix = 102, .detached = true, .client = 9 },
    };
    const capsules = [_]SessionCapsule{
        .{ .account = "carol", .sessions = &a_sessions },
        .{ .account = "dave", .sessions = &b_sessions },
    };

    const live = [_]u64{ 7, 8, 9 };

    const outcome = try roundTrip(allocator, &capsules, &live);

    try std.testing.expectEqual(@as(usize, 3), outcome.recovered);
    try std.testing.expectEqual(@as(usize, 3), outcome.attached);
    try std.testing.expectEqual(@as(usize, 0), outcome.detached);
}

test "session migration round-trip over zero capsules recovers nothing" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const capsules = [_]SessionCapsule{};
    const live = [_]u64{ 1, 2, 3 };

    const outcome = try roundTrip(allocator, &capsules, &live);

    try std.testing.expectEqual(@as(usize, 0), outcome.recovered);
    try std.testing.expectEqual(@as(usize, 0), outcome.attached);
    try std.testing.expectEqual(@as(usize, 0), outcome.detached);
}
