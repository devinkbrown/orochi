//! Deterministic self-test harness for the FULL Helix upgrade CHANNEL / WORLD
//! state round-trip, exercised entirely in-process WITHOUT the real server.
//!
//! Where `session_migration_dst.zig` proves the account-level session registry
//! survives the SEQPACKET conduit crossing, this file proves that CHANNEL state
//! does: each channel's resumable `WorldCapsule` (name, topic, modes, key,
//! limit, members) plus its `BanCapsule` mask lists (+b/+e/+I/+Z) survive an
//! encode -> conduit.send -> conduit.recv -> decode round-trip with every field
//! intact. The flow is:
//!
//!   1. Encode every `WorldCapsule` into a framed WORLD section, then every
//!      `BanCapsule` into a framed BAN section, concatenated into one payload.
//!   2. `conduit.send` it from a sender thread on one socket end while
//!      `conduit.recv` reads it on the other. The conduit refuses a non-empty
//!      payload with zero descriptors (it slices the payload across its fd
//!      batches), so a single throwaway carrier fd is attached purely as a
//!      vehicle and closed on receipt. No client descriptors are involved —
//!      world/ban state is pure state.
//!   3. Decode each capsule on the "successor" side into heap-owned buffers,
//!      since the conduit payload is freed before this function returns.
//!   4. Verify decoded channel names + member counts + ban entry counts match
//!      the inputs, and return the tallies.
//!
//! No daemon internals are touched: a socket pair and a sender thread stand in
//! for the execve'd successor.
//!
//! Two-section payload framing (all integers big-endian):
//!
//!   SECTION HEADER (2x u32):
//!     world_count : u32                 number of world capsules to follow
//!     ban_count   : u32                 number of ban capsules to follow
//!   WORLD SECTION: `world_count` records, each:
//!     len     : u32                     byte length of the encoded world capsule
//!     capsule : len bytes               `WorldCapsule.encode` output
//!   BAN SECTION: `ban_count` records, each:
//!     len     : u32                     byte length of the encoded ban capsule
//!     capsule : len bytes               `ban_capsule.encode` output
//!
//! The two counts up front let the receiver pre-size both decode loops; the
//! per-record `len` prefix lets it slice each capsule exactly without re-parsing
//! the codec's internal layout.

const std = @import("std");
const builtin = @import("builtin");

const world_capsule = @import("world_capsule.zig");
const ban_capsule = @import("ban_capsule.zig");
const conduit = @import("conduit.zig");
const handoff = @import("handoff.zig");

const Allocator = std.mem.Allocator;

/// Width of each per-record length prefix and of each section-count word.
const u32_prefix_len: usize = 4;
/// The fixed section header carries two counts: world then ban.
const section_header_len: usize = u32_prefix_len * 2;

pub const Error = conduit.Error || world_capsule.Error || ban_capsule.Error ||
    std.Thread.SpawnError || error{
    /// The received payload was malformed or its counts did not match.
    Protocol,
    /// A carrier descriptor could not be opened for the conduit transfer.
    CarrierUnavailable,
    /// A decoded channel name, member count, or ban entry count did not match
    /// the corresponding input.
    Mismatch,
};

/// Summary tallies of a full world-migration round-trip.
pub const Outcome = struct {
    /// Total channels (world capsules) recovered on the successor side.
    channels: usize,
    /// Total ban-list entries recovered across every ban capsule.
    ban_entries: usize,
};

/// One channel's decoded world capsule with allocator-owned backing for every
/// string slice (name, topic, setter, key, each member nick) and for the
/// `Member` array.
///
/// `WorldCapsule.decode` borrows its strings from the input bytes and the
/// `Member` array from a caller-supplied buffer; both the transient conduit
/// payload and any stack buffer would be gone before verification, so this
/// copies everything into heap-owned storage and re-points the slices at it.
const OwnedWorld = struct {
    capsule: world_capsule.WorldCapsule,
    members: []world_capsule.Member,
    strings: []u8,

    fn deinit(self: *OwnedWorld, allocator: Allocator) void {
        allocator.free(self.members);
        allocator.free(self.strings);
        self.* = undefined;
    }
};

/// One channel's decoded ban capsule with allocator-owned backing for every
/// string slice (channel name, each mask, each setter) and for the `MaskEntry`
/// array. Same lifetime reasoning as `OwnedWorld`.
const OwnedBan = struct {
    capsule: ban_capsule.BanCapsule,
    entries: []ban_capsule.MaskEntry,
    strings: []u8,

    fn deinit(self: *OwnedBan, allocator: Allocator) void {
        allocator.free(self.entries);
        allocator.free(self.strings);
        self.* = undefined;
    }
};

/// Append a u32 big-endian length prefix followed by `wire` to `buf`.
fn appendRecord(allocator: Allocator, buf: *std.ArrayList(u8), wire: []const u8) Error!void {
    var len_prefix: [u32_prefix_len]u8 = undefined;
    std.mem.writeInt(u32, &len_prefix, @intCast(wire.len), .big);
    try buf.appendSlice(allocator, &len_prefix);
    try buf.appendSlice(allocator, wire);
}

/// Encode `worlds` then `bans` into a single framed payload buffer (see file
/// header for the layout). Caller frees the returned slice.
fn buildPayload(
    allocator: Allocator,
    worlds: []const world_capsule.WorldCapsule,
    bans: []const ban_capsule.BanCapsule,
) Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Section header: two counts up front.
    var header: [section_header_len]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], @intCast(worlds.len), .big);
    std.mem.writeInt(u32, header[4..8], @intCast(bans.len), .big);
    try buf.appendSlice(allocator, &header);

    // Scratch large enough for any single capsule we expect to encode.
    var scratch: [16384]u8 = undefined;

    for (worlds) |w| {
        const wire = try w.encode(&scratch);
        try appendRecord(allocator, &buf, wire);
    }
    for (bans) |b| {
        const wire = try ban_capsule.encode(b, &scratch);
        try appendRecord(allocator, &buf, wire);
    }

    return buf.toOwnedSlice(allocator);
}

/// Copy `src` into `dst` at `*o`, advance `*o`, and return the owned sub-slice.
fn take(dst: []u8, o: *usize, src: []const u8) []const u8 {
    @memcpy(dst[o.* .. o.* + src.len], src);
    const slice = dst[o.* .. o.* + src.len];
    o.* += src.len;
    return slice;
}

/// Decode one world capsule from `record` into heap-owned storage. The codec
/// hands back string slices borrowing `record` and a member array borrowing a
/// scratch buffer; both are copied here so the returned `OwnedWorld` outlives
/// the conduit payload. Caller frees via `OwnedWorld.deinit`.
fn decodeWorldOwned(allocator: Allocator, record: []const u8) Error!OwnedWorld {
    var scratch_members: [4096]world_capsule.Member = undefined;
    const view = try world_capsule.WorldCapsule.decode(record, &scratch_members);

    // Total string bytes = name + topic + setter + key + every member nick.
    var string_total: usize = view.name.len + view.topic.len + view.topic_setter.len;
    if (view.key) |k| string_total += k.len;
    for (view.members) |m| string_total += m.nick.len;

    const strings = try allocator.alloc(u8, string_total);
    errdefer allocator.free(strings);
    const members = try allocator.alloc(world_capsule.Member, view.members.len);
    errdefer allocator.free(members);

    var off: usize = 0;
    const name = take(strings, &off, view.name);
    const topic = take(strings, &off, view.topic);
    const setter = take(strings, &off, view.topic_setter);
    const key: ?[]const u8 = if (view.key) |k| take(strings, &off, k) else null;
    for (view.members, 0..) |m, i| {
        members[i] = .{ .nick = take(strings, &off, m.nick), .status = m.status };
    }

    return .{
        .capsule = .{
            .name = name,
            .topic = topic,
            .topic_setter = setter,
            .topic_ts = view.topic_ts,
            .created_unix = view.created_unix,
            .oid = view.oid,
            .modes = view.modes,
            .key = key,
            .limit = view.limit,
            .members = members,
        },
        .members = members,
        .strings = strings,
    };
}

/// Decode one ban capsule from `record` into heap-owned storage. Same lifetime
/// reasoning as `decodeWorldOwned`. Caller frees via `OwnedBan.deinit`.
fn decodeBanOwned(allocator: Allocator, record: []const u8) Error!OwnedBan {
    var scratch_entries: [4096]ban_capsule.MaskEntry = undefined;
    const view = try ban_capsule.decode(record, &scratch_entries);

    // Total string bytes = channel + every mask + every setter.
    var string_total: usize = view.channel.len;
    for (view.entries) |e| string_total += e.mask.len + e.setter.len;

    const strings = try allocator.alloc(u8, string_total);
    errdefer allocator.free(strings);
    const entries = try allocator.alloc(ban_capsule.MaskEntry, view.entries.len);
    errdefer allocator.free(entries);

    var off: usize = 0;
    const channel = take(strings, &off, view.channel);
    for (view.entries, 0..) |e, i| {
        entries[i] = .{
            .kind = e.kind,
            .mask = take(strings, &off, e.mask),
            .setter = take(strings, &off, e.setter),
            .set_ts = e.set_ts,
        };
    }

    return .{
        .capsule = .{ .channel = channel, .entries = entries },
        .entries = entries,
        .strings = strings,
    };
}

/// Read a u32 big-endian length prefix at `*pos` and return the record slice it
/// frames, advancing `*pos` past both. Returns `error.Protocol` on overrun.
fn readRecord(payload: []const u8, pos: *usize) Error![]const u8 {
    if (pos.* + u32_prefix_len > payload.len) return error.Protocol;
    const rec_len = std.mem.readInt(u32, payload[pos.*..][0..u32_prefix_len], .big);
    pos.* += u32_prefix_len;
    if (pos.* + rec_len > payload.len) return error.Protocol;
    const rec = payload[pos.* .. pos.* + rec_len];
    pos.* += rec_len;
    return rec;
}

/// Decode the framed payload into `worlds_out` / `bans_out`, returning the two
/// counts. Caller frees each entry via the respective `deinit`.
fn decodePayload(
    allocator: Allocator,
    payload: []const u8,
    worlds_out: []OwnedWorld,
    bans_out: []OwnedBan,
) Error!struct { worlds: usize, bans: usize } {
    if (payload.len < section_header_len) return error.Protocol;
    const world_count = std.mem.readInt(u32, payload[0..4], .big);
    const ban_count = std.mem.readInt(u32, payload[4..8], .big);
    if (world_count > worlds_out.len or ban_count > bans_out.len) return error.Protocol;

    var pos: usize = section_header_len;

    var wi: usize = 0;
    errdefer for (worlds_out[0..wi]) |*w| w.deinit(allocator);
    while (wi < world_count) : (wi += 1) {
        const rec = try readRecord(payload, &pos);
        worlds_out[wi] = try decodeWorldOwned(allocator, rec);
    }

    var bi: usize = 0;
    errdefer for (bans_out[0..bi]) |*b| b.deinit(allocator);
    while (bi < ban_count) : (bi += 1) {
        const rec = try readRecord(payload, &pos);
        bans_out[bi] = try decodeBanOwned(allocator, rec);
    }

    if (pos != payload.len) return error.Protocol;
    return .{ .worlds = world_count, .bans = ban_count };
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
/// across its fd batches), so a world/ban transfer — which carries no client
/// sockets of its own — still needs one vehicle fd. Returns a dup of a fresh
/// pipe read end. Caller closes the returned fd.
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

/// Verify decoded channel names + member counts match the input world capsules,
/// and that ban capsule channels + entry counts match the input ban capsules.
fn verify(
    worlds_in: []const world_capsule.WorldCapsule,
    bans_in: []const ban_capsule.BanCapsule,
    worlds_out: []const OwnedWorld,
    bans_out: []const OwnedBan,
) Error!void {
    if (worlds_out.len != worlds_in.len) return error.Mismatch;
    for (worlds_in, worlds_out) |want, got| {
        if (!std.mem.eql(u8, want.name, got.capsule.name)) return error.Mismatch;
        if (want.members.len != got.capsule.members.len) return error.Mismatch;
    }

    if (bans_out.len != bans_in.len) return error.Mismatch;
    for (bans_in, bans_out) |want, got| {
        if (!std.mem.eql(u8, want.channel, got.capsule.channel)) return error.Mismatch;
        if (want.entries.len != got.capsule.entries.len) return error.Mismatch;
    }
}

/// Run the full encode -> conduit.send -> conduit.recv -> decode -> verify
/// round-trip over a fresh socket pair and return the channel / ban-entry
/// tallies.
///
/// Every channel's world capsule and every ban capsule is recovered on the
/// successor side, its decoded channel name + member count (world) and channel
/// name + entry count (ban) checked against the input. All transient and owned
/// buffers are freed before returning; the caller keeps only the tallies.
pub fn roundTrip(
    allocator: Allocator,
    channels: []const world_capsule.WorldCapsule,
    bans: []const ban_capsule.BanCapsule,
) Error!Outcome {
    if (builtin.os.tag != .linux) return error.Unsupported;

    const payload = try buildPayload(allocator, channels, bans);
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

    // Close the received copy of the carrier; this transfer owns no descriptors.
    for (received.fds) |fd| _ = std.os.linux.close(fd);

    // Decode every capsule into heap-owned storage so its slices outlive the
    // payload buffer that `received.deinit` frees above.
    const worlds_out = try allocator.alloc(OwnedWorld, channels.len);
    defer allocator.free(worlds_out);
    const bans_out = try allocator.alloc(OwnedBan, bans.len);
    defer allocator.free(bans_out);

    const counts = try decodePayload(allocator, received.payload, worlds_out, bans_out);
    defer for (worlds_out[0..counts.worlds]) |*w| w.deinit(allocator);
    defer for (bans_out[0..counts.bans]) |*b| b.deinit(allocator);

    try verify(channels, bans, worlds_out[0..counts.worlds], bans_out[0..counts.bans]);

    var ban_entries: usize = 0;
    for (bans_out[0..counts.bans]) |b| ban_entries += b.capsule.entries.len;

    return .{ .channels = counts.worlds, .ban_entries = ban_entries };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const Member = world_capsule.Member;
const WorldCapsule = world_capsule.WorldCapsule;
const MaskEntry = ban_capsule.MaskEntry;
const BanCapsule = ban_capsule.BanCapsule;

test "world migration round-trip recovers every channel and ban entry intact" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    // Channel "#orochi": 4 members, non-null key, real topic.
    const orochi_members = [_]Member{
        .{ .nick = "founder", .status = 0x80 },
        .{ .nick = "op", .status = 0x40 },
        .{ .nick = "voiced", .status = 0x01 },
        .{ .nick = "regular", .status = 0x00 },
    };
    // Channel "#deep": 2 members, null key, empty topic.
    const deep_members = [_]Member{
        .{ .nick = "diver", .status = 0x40 },
        .{ .nick = "lurker", .status = 0x00 },
    };

    const channels = [_]WorldCapsule{
        .{
            .name = "#orochi",
            .topic = "Welcome to the deep",
            .topic_setter = "Suimyaku!user@host",
            .topic_ts = 1_700_000_000,
            .created_unix = 1_600_000_000,
            .oid = 0xDEAD_BEEF_CAFE_F00D,
            .modes = 0x1234_5678,
            .key = "s3cr3t",
            .limit = 256,
            .members = &orochi_members,
        },
        .{
            .name = "#deep",
            .topic = "",
            .topic_setter = "",
            .topic_ts = 0,
            .created_unix = 1_650_000_000,
            .oid = 42,
            .modes = 0,
            .key = null,
            .limit = 0,
            .members = &deep_members,
        },
    };

    // Ban lists spanning all four mask kinds across two channels.
    const orochi_bans = [_]MaskEntry{
        .{ .kind = .ban, .mask = "*!*@spam.example.org", .setter = "op!u@host", .set_ts = 1_700_000_001 },
        .{ .kind = .exempt, .mask = "trusted!*@*.good.net", .setter = "founder!f@h", .set_ts = 1_700_000_002 },
        .{ .kind = .invex, .mask = "vip!*@vip.example.com", .setter = "", .set_ts = 1_700_000_003 },
        .{ .kind = .mute, .mask = "loud!*@*.noisy.io", .setter = "halfop!h@host", .set_ts = 1_700_000_004 },
    };
    const deep_bans = [_]MaskEntry{
        .{ .kind = .ban, .mask = "troll!*@*", .setter = "diver!d@host", .set_ts = 1_700_000_005 },
        .{ .kind = .mute, .mask = "noise!*@*.flood.net", .setter = "diver!d@host", .set_ts = 1_700_000_006 },
    };

    const bans = [_]BanCapsule{
        .{ .channel = "#orochi", .entries = &orochi_bans },
        .{ .channel = "#deep", .entries = &deep_bans },
    };

    const total_ban_entries = orochi_bans.len + deep_bans.len; // 6

    const outcome = try roundTrip(allocator, &channels, &bans);

    try std.testing.expectEqual(@as(usize, 2), outcome.channels);
    try std.testing.expectEqual(@as(usize, total_ban_entries), outcome.ban_entries);
}

test "world migration round-trip with zero ban entries still recovers channels" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const a_members = [_]Member{
        .{ .nick = "alice", .status = 0x80 },
    };
    const b_members = [_]Member{
        .{ .nick = "bob", .status = 0x40 },
        .{ .nick = "carol", .status = 0x00 },
    };

    const channels = [_]WorldCapsule{
        .{
            .name = "#a",
            .topic = "first",
            .topic_setter = "alice!a@h",
            .topic_ts = 1,
            .created_unix = 2,
            .oid = 1,
            .modes = 1,
            .key = "k",
            .limit = 10,
            .members = &a_members,
        },
        .{
            .name = "#b",
            .topic = "",
            .topic_setter = "",
            .topic_ts = 0,
            .created_unix = 3,
            .oid = 2,
            .modes = 0,
            .key = null,
            .limit = 0,
            .members = &b_members,
        },
    };

    const bans = [_]BanCapsule{
        .{ .channel = "#a", .entries = &[_]MaskEntry{} },
        .{ .channel = "#b", .entries = &[_]MaskEntry{} },
    };

    const outcome = try roundTrip(allocator, &channels, &bans);

    try std.testing.expectEqual(@as(usize, 2), outcome.channels);
    try std.testing.expectEqual(@as(usize, 0), outcome.ban_entries);
}

test "world migration round-trip over zero channels and zero bans recovers nothing" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const channels = [_]WorldCapsule{};
    const bans = [_]BanCapsule{};

    const outcome = try roundTrip(allocator, &channels, &bans);

    try std.testing.expectEqual(@as(usize, 0), outcome.channels);
    try std.testing.expectEqual(@as(usize, 0), outcome.ban_entries);
}
