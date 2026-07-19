// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable, daemon-global replay authority for signed Event Spine v2 floods.
//!
//! This is deliberately a typed wrapper around `relay_v2_replay_guard.Guard`:
//! both protocols need the same greatest-W plus retired-HLC semantics, while
//! Event Spine retains a distinct checkpoint envelope and admission API. A
//! lossy per-link SeenSet is only a reflection optimization and must never be
//! used as the delivery/history authority.
const std = @import("std");

const oper_event = @import("../proto/oper_event.zig");
const replay = @import("relay_v2_replay_guard.zig");

pub const Config = replay.Config;

pub const Decision = enum {
    accepted,
    duplicate,
    equivocation,
    retired,
    origin_capacity,
    origin_mismatch,
    bad_signature,
    invalid_semantic,
    future_skew,
};

/// One atomic verify-and-admit outcome. Only `accepted` carries an event id,
/// and that id is the exact value derived from the same authenticated event
/// whose replay state was mutated. Daemon callers must use this payload for
/// history/msgid publication instead of verifying or deriving an id again.
pub const Admission = union(Decision) {
    accepted: oper_event.EventId,
    duplicate,
    equivocation,
    retired,
    origin_capacity,
    origin_mismatch,
    bad_signature,
    invalid_semantic,
    future_skew,
};

pub const InitError = replay.InitError;
pub const CheckpointError = replay.CheckpointError;

pub const Guard = struct {
    /// The daemon serializes this global guard under the same Event Spine/world
    /// mutation lane used for local delivery, forwarding, and checkpointing.
    allocator: std.mem.Allocator,
    config: Config,
    inner: replay.Guard,

    pub fn init(allocator: std.mem.Allocator, config: Config) InitError!Guard {
        return .{
            .allocator = allocator,
            .config = config,
            .inner = try replay.Guard.init(allocator, config),
        };
    }

    pub fn deinit(self: *Guard) void {
        self.inner.deinit();
        self.* = undefined;
    }

    /// Authenticate first, reject implausibly-future HLCs without mutation, then
    /// enter the author's full public-key namespace. `now_ms` is Unix epoch ms.
    /// Only `.accepted` authorizes local delivery, history insertion, and
    /// re-forwarding. Every other decision is a no-delivery terminal result.
    pub fn admit(
        self: *Guard,
        ev: oper_event.SignedOperEventV2,
        now_ms: u64,
        max_future_skew_ms: u64,
    ) std.mem.Allocator.Error!Admission {
        const verified = switch (oper_event.verifyAndEventId(ev)) {
            .verified => |identity| identity,
            .origin_mismatch => return .origin_mismatch,
            .bad_signature => return .bad_signature,
            .invalid_semantic => return .invalid_semantic,
        };
        const latest_physical = std.math.add(u64, now_ms, max_future_skew_ms) catch std.math.maxInt(u64);
        if (ev.originTimeMs() > latest_physical) return .future_skew;
        return mapReplayDecision(
            try self.inner.admit(verified.origin_pubkey, ev.hlc, verified.event_id),
            verified.event_id,
        );
    }

    /// Canonical event-specific envelope around the reused replay-guard image.
    /// The distinct magic/domain prevents accidentally restoring a MESSAGE_V2
    /// checkpoint into the Event Spine authority (or vice versa).
    pub fn encodeCheckpoint(self: *const Guard, allocator: std.mem.Allocator) CheckpointError![]u8 {
        const inner = try self.inner.encodeCheckpoint(allocator);
        defer allocator.free(inner);
        if (inner.len > replay.hard_max_checkpoint_bytes) return error.CheckpointTooLarge;
        const prefix_len = checkpoint_header_len + inner.len;
        const total_len = std.math.add(usize, prefix_len, checksum_len) catch return error.CheckpointTooLarge;
        if (total_len > max_checkpoint_bytes) return error.CheckpointTooLarge;
        const out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);
        @memcpy(out[0..checkpoint_magic.len], &checkpoint_magic);
        out[4] = checkpoint_version;
        out[5] = 0; // reserved flags
        writeU32(out[6..10], @intCast(inner.len));
        @memcpy(out[checkpoint_header_len..prefix_len], inner);
        checkpointChecksum(out[0..prefix_len], out[prefix_len..][0..checksum_len]);
        return out;
    }

    pub fn decodeCheckpoint(
        allocator: std.mem.Allocator,
        config: Config,
        bytes: []const u8,
    ) CheckpointError!Guard {
        const inner_bytes = try decodeEnvelope(bytes);
        return .{
            .allocator = allocator,
            .config = config,
            .inner = try replay.Guard.decodeCheckpoint(allocator, config, inner_bytes),
        };
    }

    /// Transactional replacement: malformed, stale-config, capacity, and OOM
    /// failures leave the live replay authority unchanged.
    pub fn replaceFromCheckpoint(self: *Guard, bytes: []const u8) CheckpointError!void {
        var replacement = try Guard.decodeCheckpoint(self.allocator, self.config, bytes);
        const previous = self.*;
        self.* = replacement;
        replacement = previous;
        replacement.deinit();
    }
};

fn mapReplayDecision(decision: replay.Decision, event_id: oper_event.EventId) Admission {
    return switch (decision) {
        .accepted => .{ .accepted = event_id },
        .duplicate => .duplicate,
        .equivocation => .equivocation,
        .retired => .retired,
        .origin_capacity => .origin_capacity,
    };
}

const checkpoint_magic = [_]u8{ 'E', 'S', 'G', '2' };
const checkpoint_version: u8 = 1;
const checkpoint_header_len: usize = 10;
const checksum_len: usize = std.crypto.hash.Blake3.digest_length;
const max_checkpoint_bytes: usize = replay.hard_max_checkpoint_bytes + checkpoint_header_len + checksum_len;
const checkpoint_checksum_domain = "orochi-event-spine-replay-checkpoint-v1";

/// Allocation-free outer discriminator for Helix mesh-checkpoint selection.
/// This intentionally checks only the unambiguous ESG2 magic; callers must pass
/// matching bytes through `decodeCheckpoint` for canonical/version/config
/// validation before staging or publishing authority.
pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= checkpoint_magic.len and
        std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic);
}

/// Allocation-free strict validation of the complete ESG2 envelope and its
/// canonical replay image. The returned limits are the authority encoded by the
/// producer; the daemon's staging decode must still require exact equality with
/// its operator-owned expected `Config`.
pub fn validateCheckpoint(bytes: []const u8) CheckpointError!Config {
    const inner = try decodeEnvelope(bytes);
    return replay.validateCheckpoint(inner);
}

fn decodeEnvelope(bytes: []const u8) CheckpointError![]const u8 {
    if (bytes.len < checkpoint_header_len + checksum_len) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic)) return error.BadMagic;
    if (bytes[4] != checkpoint_version) return error.UnsupportedVersion;
    if (bytes[5] != 0) return error.InvalidField;
    const inner_len: usize = readU32(bytes[6..10]);
    if (inner_len > replay.hard_max_checkpoint_bytes) return error.CheckpointTooLarge;
    const prefix_len = std.math.add(usize, checkpoint_header_len, inner_len) catch return error.CheckpointTooLarge;
    const expected_len = std.math.add(usize, prefix_len, checksum_len) catch return error.CheckpointTooLarge;
    if (expected_len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;
    var actual: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0..prefix_len], &actual);
    if (!std.mem.eql(u8, &actual, bytes[prefix_len..])) return error.ChecksumMismatch;
    return bytes[checkpoint_header_len..prefix_len];
}

fn checkpointChecksum(prefix: []const u8, out: *[checksum_len]u8) void {
    var h = std.crypto.hash.Blake3.init(.{});
    h.update(checkpoint_checksum_domain);
    h.update(prefix);
    h.final(out);
}

fn readU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .big);
}

fn writeU32(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .big);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const sign = @import("../crypto/sign.zig");
const mesh_clock = @import("../substrate/undertow/mesh_clock.zig");

fn testEvent(
    kp: *const sign.KeyPair,
    hlc: u64,
    message: []const u8,
    pubkey: *[oper_event.pubkey_len]u8,
    signature: *[oper_event.sig_len]u8,
) !oper_event.SignedOperEventV2 {
    var ev = oper_event.SignedOperEventV2{
        .category = 1,
        .severity = 2,
        .origin_node = oper_event.originShortId(kp.public_key),
        .hlc = hlc,
        .origin_server = "mesh.test",
        .subject = "#mesh",
        .message = message,
    };
    try oper_event.stampOrigin(&ev, kp, pubkey, signature);
    return ev;
}

fn expectDecision(expected: Decision, admission: Admission) !void {
    try testing.expectEqual(expected, std.meta.activeTag(admission));
}

test "event spine replay guard rejects duplicates equivocation and future skew before delivery" {
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x31)));
    defer kp.deinit();
    const now_ms: u64 = 1_700_000_000_000;
    const hlc = (now_ms << mesh_clock.seq_bits) | 1;
    var pk_a: [oper_event.pubkey_len]u8 = undefined;
    var sig_a: [oper_event.sig_len]u8 = undefined;
    const a = try testEvent(&kp, hlc, "one event", &pk_a, &sig_a);
    var pk_b: [oper_event.pubkey_len]u8 = undefined;
    var sig_b: [oper_event.sig_len]u8 = undefined;
    const b = try testEvent(&kp, hlc, "different event at the same HLC", &pk_b, &sig_b);

    var guard = try Guard.init(testing.allocator, .{ .window_size = 3, .max_origins = 1 });
    defer guard.deinit();
    const accepted = try guard.admit(a, now_ms, 100);
    try expectDecision(.accepted, accepted);
    const expected_id = try oper_event.eventId(a);
    try testing.expectEqual(expected_id, accepted.accepted);
    try expectDecision(.duplicate, try guard.admit(a, now_ms, 100));
    try expectDecision(.equivocation, try guard.admit(b, now_ms, 100));

    var pk_future: [oper_event.pubkey_len]u8 = undefined;
    var sig_future: [oper_event.sig_len]u8 = undefined;
    const future = try testEvent(&kp, ((now_ms + 101) << mesh_clock.seq_bits) | 2, "future", &pk_future, &sig_future);
    try expectDecision(.future_skew, try guard.admit(future, now_ms, 100));
    // A future-skew rejection carries no id and mutates no replay state. Once
    // wall time legitimately reaches the event, the identical object is live.
    try expectDecision(.accepted, try guard.admit(future, now_ms + 101, 100));
}

test "event spine replay guard verifies before admission so forgery cannot poison a valid event" {
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x32)));
    defer kp.deinit();
    const now_ms: u64 = 1_700_000_000_000;
    var pk: [oper_event.pubkey_len]u8 = undefined;
    var sig: [oper_event.sig_len]u8 = undefined;
    const valid = try testEvent(&kp, (now_ms << mesh_clock.seq_bits) | 1, "valid", &pk, &sig);
    var forged = valid;
    forged.message = "forged";

    var guard = try Guard.init(testing.allocator, .{ .window_size = 3, .max_origins = 1 });
    defer guard.deinit();
    try expectDecision(.bad_signature, try guard.admit(forged, now_ms, 100));
    try expectDecision(.accepted, try guard.admit(valid, now_ms, 100));
}

test "event spine replay guard permanently retires evictions across checkpoint restore" {
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x33)));
    defer kp.deinit();
    const now_ms: u64 = 1_700_000_000_000;
    var guard = try Guard.init(testing.allocator, .{ .window_size = 2, .max_origins = 1 });
    defer guard.deinit();
    var events: [3]oper_event.SignedOperEventV2 = undefined;
    var pks: [3][oper_event.pubkey_len]u8 = undefined;
    var sigs: [3][oper_event.sig_len]u8 = undefined;
    var messages: [3][8]u8 = undefined;
    for (&events, 0..) |*ev, i| {
        const text = try std.fmt.bufPrint(&messages[i], "event-{d}", .{i});
        ev.* = try testEvent(&kp, (now_ms << mesh_clock.seq_bits) | @as(u64, @intCast(i + 1)), text, &pks[i], &sigs[i]);
        try expectDecision(.accepted, try guard.admit(ev.*, now_ms, 100));
    }
    try expectDecision(.retired, try guard.admit(events[0], now_ms, 100));

    const checkpoint = try guard.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    var restored = try Guard.decodeCheckpoint(testing.allocator, .{ .window_size = 2, .max_origins = 1 }, checkpoint);
    defer restored.deinit();
    try expectDecision(.retired, try restored.admit(events[0], now_ms, 100));
    try expectDecision(.duplicate, try restored.admit(events[1], now_ms, 100));
}

test "event spine replay checkpoint is deterministic typed and strict" {
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x34)));
    defer kp.deinit();
    const now_ms: u64 = 1_700_000_000_000;
    var pk: [oper_event.pubkey_len]u8 = undefined;
    var sig: [oper_event.sig_len]u8 = undefined;
    const ev = try testEvent(&kp, (now_ms << mesh_clock.seq_bits) | 1, "checkpoint", &pk, &sig);
    var guard = try Guard.init(testing.allocator, .{ .window_size = 2, .max_origins = 1 });
    defer guard.deinit();
    _ = try guard.admit(ev, now_ms, 100);
    const a = try guard.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(a);
    const b = try guard.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(b);
    try testing.expectEqualSlices(u8, a, b);
    try testing.expect(isCheckpoint(a));
    const encoded_config = try validateCheckpoint(a);
    try testing.expectEqual(@as(usize, 2), encoded_config.window_size);
    try testing.expectEqual(@as(usize, 1), encoded_config.max_origins);

    for (0..a.len) |cut| try testing.expectError(error.Truncated, Guard.decodeCheckpoint(
        testing.allocator,
        .{ .window_size = 2, .max_origins = 1 },
        a[0..cut],
    ));
    var mutated = try testing.allocator.dupe(u8, a);
    defer testing.allocator.free(mutated);
    mutated[4] = checkpoint_version + 1;
    try testing.expectError(error.UnsupportedVersion, Guard.decodeCheckpoint(
        testing.allocator,
        .{ .window_size = 2, .max_origins = 1 },
        mutated,
    ));
    @memcpy(mutated, a);
    mutated[5] = 1;
    try testing.expectError(error.InvalidField, Guard.decodeCheckpoint(
        testing.allocator,
        .{ .window_size = 2, .max_origins = 1 },
        mutated,
    ));
    mutated[5] = 0;
    mutated[0] ^= 1;
    try testing.expectError(error.BadMagic, Guard.decodeCheckpoint(
        testing.allocator,
        .{ .window_size = 2, .max_origins = 1 },
        mutated,
    ));
    @memcpy(mutated, a);
    mutated[checkpoint_header_len] ^= 1;
    try testing.expectError(error.ChecksumMismatch, Guard.decodeCheckpoint(
        testing.allocator,
        .{ .window_size = 2, .max_origins = 1 },
        mutated,
    ));
    @memcpy(mutated, a);
    const declared_inner_len = readU32(mutated[6..10]);
    writeU32(mutated[6..10], declared_inner_len - 1);
    try testing.expectError(error.TrailingBytes, Guard.decodeCheckpoint(
        testing.allocator,
        .{ .window_size = 2, .max_origins = 1 },
        mutated,
    ));
    @memcpy(mutated, a);
    writeU32(mutated[6..10], declared_inner_len + 1);
    try testing.expectError(error.Truncated, Guard.decodeCheckpoint(
        testing.allocator,
        .{ .window_size = 2, .max_origins = 1 },
        mutated,
    ));
    var trailing = try testing.allocator.alloc(u8, a.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..a.len], a);
    trailing[a.len] = 0;
    try testing.expectError(error.TrailingBytes, Guard.decodeCheckpoint(
        testing.allocator,
        .{ .window_size = 2, .max_origins = 1 },
        trailing,
    ));
    try testing.expectError(error.ConfigMismatch, Guard.decodeCheckpoint(
        testing.allocator,
        .{ .window_size = 3, .max_origins = 1 },
        a,
    ));
}

test "event spine replay guard allocation sweeps are leak-free and transactional" {
    const cfg = Config{ .window_size = 4, .max_origins = 4 };
    const now_ms: u64 = 1_700_000_000_000;
    var source_kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x41)));
    defer source_kp.deinit();
    var source_pk: [oper_event.pubkey_len]u8 = undefined;
    var source_sig: [oper_event.sig_len]u8 = undefined;
    const source_event = try testEvent(
        &source_kp,
        (now_ms << mesh_clock.seq_bits) | 1,
        "source",
        &source_pk,
        &source_sig,
    );
    var source = try Guard.init(testing.allocator, cfg);
    defer source.deinit();
    try expectDecision(.accepted, try source.admit(source_event, now_ms, 100));

    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, guard: *const Guard) !void {
            const bytes = try guard.encodeCheckpoint(allocator);
            defer allocator.free(bytes);
            try testing.expect(bytes.len > checkpoint_header_len + checksum_len);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, EncodeSweep.run, .{&source});

    const checkpoint = try source.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, config: Config, bytes: []const u8) !void {
            var restored = try Guard.decodeCheckpoint(allocator, config, bytes);
            defer restored.deinit();
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, DecodeSweep.run, .{ cfg, checkpoint });

    var new_origin_kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x42)));
    defer new_origin_kp.deinit();
    var new_origin_pk: [oper_event.pubkey_len]u8 = undefined;
    var new_origin_sig: [oper_event.sig_len]u8 = undefined;
    const new_origin_event = try testEvent(
        &new_origin_kp,
        (now_ms << mesh_clock.seq_bits) | 2,
        "new-origin",
        &new_origin_pk,
        &new_origin_sig,
    );
    const AdmitSweep = struct {
        fn run(
            allocator: std.mem.Allocator,
            config: Config,
            ev: oper_event.SignedOperEventV2,
            now: u64,
        ) !void {
            var guard = try Guard.init(allocator, config);
            defer guard.deinit();
            const before = try guard.encodeCheckpoint(testing.allocator);
            defer testing.allocator.free(before);
            const decision = guard.admit(ev, now, 100) catch |err| {
                const after = try guard.encodeCheckpoint(testing.allocator);
                defer testing.allocator.free(after);
                try testing.expectEqualSlices(u8, before, after);
                return err;
            };
            try expectDecision(.accepted, decision);
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        AdmitSweep.run,
        .{ cfg, new_origin_event, now_ms },
    );

    const ReplaceSweep = struct {
        fn run(
            allocator: std.mem.Allocator,
            config: Config,
            bytes: []const u8,
            source_ev: oper_event.SignedOperEventV2,
            sentinel_ev: oper_event.SignedOperEventV2,
            now: u64,
        ) !void {
            var target = try Guard.init(allocator, config);
            defer target.deinit();
            try expectDecision(.accepted, try target.admit(sentinel_ev, now, 100));
            const before = try target.encodeCheckpoint(testing.allocator);
            defer testing.allocator.free(before);
            target.replaceFromCheckpoint(bytes) catch |err| {
                const after = try target.encodeCheckpoint(testing.allocator);
                defer testing.allocator.free(after);
                try testing.expectEqualSlices(u8, before, after);
                return err;
            };
            try expectDecision(.duplicate, try target.admit(source_ev, now, 100));
            try expectDecision(.accepted, try target.admit(sentinel_ev, now, 100));
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        ReplaceSweep.run,
        .{ cfg, checkpoint, source_event, new_origin_event, now_ms },
    );
}
