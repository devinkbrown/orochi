// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Monotonic MESSAGE_V2 authoring activation carried by current Helix handoff.
//!
//! Compatibility nodes receive and forward MESSAGE_V2 but author only the
//! legacy representation. Operators first stage the same non-zero epoch and
//! full-mesh roster on every node, then change only `mode` to `active`.
//! Active nodes author MESSAGE_V2 exclusively and may never hot-downgrade.
const std = @import("std");

pub const digest_len = std.crypto.hash.Blake3.digest_length;
pub const public_key_len: usize = 32;
pub const PublicKey = [public_key_len]u8;
pub const max_roster_entries: usize = 4096;
const roster_digest_domain = "orochi-message-v2-activation-roster-v1\x00";

pub const Mode = enum(u8) {
    compat = 0,
    active = 1,
};

pub const State = struct {
    mode: Mode = .compat,
    activation_epoch: u64 = 0,
    roster_digest: [digest_len]u8 = @splat(0),
};

pub const Error = error{
    DuplicateRosterKey,
    InvalidPublicKey,
    InvalidRoster,
    LocalIdentityMismatch,
    MissingLocalIdentity,
    MissingActivationPlan,
    IncompleteActivationPlan,
} || std.mem.Allocator.Error;

pub fn validate(state: State) Error!void {
    const digest_is_zero = std.mem.allEqual(u8, &state.roster_digest, 0);
    if ((state.activation_epoch == 0) != digest_is_zero)
        return error.IncompleteActivationPlan;
    if (state.mode == .active and state.activation_epoch == 0)
        return error.MissingActivationPlan;
}

/// Decode one Ed25519 public identity from the two deployment spellings Orochi
/// accepts. The canonical roster always hashes raw 32-byte keys, never their
/// case-sensitive hex/base64 text.
pub fn decodePublicKey(text: []const u8) Error!PublicKey {
    var out: PublicKey = undefined;
    if (text.len == public_key_len * 2) {
        _ = std.fmt.hexToBytes(&out, text) catch return error.InvalidPublicKey;
        return out;
    }
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(text) catch
        return error.InvalidPublicKey;
    if (decoded_len != public_key_len) return error.InvalidPublicKey;
    std.base64.standard.Decoder.decode(&out, text) catch return error.InvalidPublicKey;
    return out;
}

pub const CanonicalRoster = struct {
    allocator: std.mem.Allocator,
    keys: []PublicKey,
    digest: [digest_len]u8,

    pub fn deinit(self: *CanonicalRoster) void {
        self.allocator.free(self.keys);
        self.* = undefined;
    }

    pub fn contains(self: *const CanonicalRoster, wanted: PublicKey) bool {
        for (self.keys) |key| {
            if (std.crypto.timing_safe.eql(PublicKey, key, wanted)) return true;
        }
        return false;
    }
};

/// Decode, sort, de-duplicate, and hash the complete deployment inventory.
/// Every fallible step precedes publication; callers own the returned roster.
pub fn canonicalizeRoster(
    allocator: std.mem.Allocator,
    encoded: []const []const u8,
) Error!CanonicalRoster {
    if (encoded.len == 0 or encoded.len > max_roster_entries) return error.InvalidRoster;
    const keys = try allocator.alloc(PublicKey, encoded.len);
    errdefer allocator.free(keys);
    for (encoded, keys) |text, *key| key.* = try decodePublicKey(text);
    std.mem.sort(PublicKey, keys, {}, keyLessThan);
    for (keys[1..], keys[0 .. keys.len - 1]) |key, previous| {
        if (std.crypto.timing_safe.eql(PublicKey, key, previous)) return error.DuplicateRosterKey;
    }
    return .{
        .allocator = allocator,
        .keys = keys,
        .digest = rosterDigest(keys),
    };
}

/// Build the exact authority persisted in MHLC v3 from operator configuration.
pub fn stateFromConfig(
    allocator: std.mem.Allocator,
    mode: Mode,
    activation_epoch: u64,
    encoded_roster: []const []const u8,
) Error!State {
    if (activation_epoch == 0 and encoded_roster.len == 0) {
        const state = State{ .mode = mode };
        try validate(state);
        return state;
    }
    if (activation_epoch == 0 or encoded_roster.len == 0) return error.IncompleteActivationPlan;
    var roster = try canonicalizeRoster(allocator, encoded_roster);
    defer roster.deinit();
    const state = State{
        .mode = mode,
        .activation_epoch = activation_epoch,
        .roster_digest = roster.digest,
    };
    try validate(state);
    return state;
}

/// Bind the operator's public identity assertion to the actual private node
/// identity loaded for this process. Activation cannot proceed on a merely
/// roster-present but differently keyed daemon.
pub fn bindConfiguredPublicKey(configured: ?[]const u8, runtime: ?PublicKey) Error!PublicKey {
    const configured_key = try decodePublicKey(configured orelse return error.MissingLocalIdentity);
    const runtime_key = runtime orelse return error.MissingLocalIdentity;
    if (!std.crypto.timing_safe.eql(PublicKey, configured_key, runtime_key))
        return error.LocalIdentityMismatch;
    return runtime_key;
}

fn keyLessThan(_: void, lhs: PublicKey, rhs: PublicKey) bool {
    return std.mem.order(u8, &lhs, &rhs) == .lt;
}

fn rosterDigest(keys: []const PublicKey) [digest_len]u8 {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(roster_digest_domain);
    var count: [4]u8 = undefined;
    std.mem.writeInt(u32, &count, @intCast(keys.len), .big);
    hasher.update(&count);
    for (keys) |key| hasher.update(&key);
    var digest: [digest_len]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

/// Validate a current Helix transition against the successor's configured
/// state. Compatibility mode may stage an initial plan or supersede it only
/// with a strictly newer epoch. A staged epoch is immutable: it cannot be
/// removed, decreased, or rebound to another roster. Activation requires the
/// exact plan already carried by the predecessor. Once active, mode, epoch,
/// and roster are immutable.
pub fn permitsHandoff(predecessor: State, successor: State) bool {
    validate(predecessor) catch return false;
    validate(successor) catch return false;

    return switch (predecessor.mode) {
        .compat => switch (successor.mode) {
            .compat => if (predecessor.activation_epoch == 0)
                true
            else if (successor.activation_epoch > predecessor.activation_epoch)
                true
            else
                predecessor.activation_epoch == successor.activation_epoch and
                    std.crypto.timing_safe.eql(
                        [digest_len]u8,
                        predecessor.roster_digest,
                        successor.roster_digest,
                    ),
            .active => predecessor.activation_epoch != 0 and
                predecessor.activation_epoch == successor.activation_epoch and
                std.crypto.timing_safe.eql(
                    [digest_len]u8,
                    predecessor.roster_digest,
                    successor.roster_digest,
                ),
        },
        .active => successor.mode == .active and
            predecessor.activation_epoch == successor.activation_epoch and
            std.crypto.timing_safe.eql(
                [digest_len]u8,
                predecessor.roster_digest,
                successor.roster_digest,
            ),
    };
}

const testing = std.testing;

test "relay v2 activation requires a complete plan" {
    try validate(.{});
    try testing.expectError(error.MissingActivationPlan, validate(.{ .mode = .active }));
    try testing.expectError(error.IncompleteActivationPlan, validate(.{ .activation_epoch = 7 }));
    try testing.expectError(error.IncompleteActivationPlan, validate(.{ .roster_digest = @splat(1) }));
    try validate(.{ .mode = .active, .activation_epoch = 7, .roster_digest = @splat(1) });
}

test "relay v2 activation handoff is staged and monotonic" {
    const default = State{};
    const staged = State{ .activation_epoch = 7, .roster_digest = @splat(1) };
    const active = State{ .mode = .active, .activation_epoch = 7, .roster_digest = @splat(1) };
    const newer = State{ .activation_epoch = 8, .roster_digest = @splat(2) };
    const rebound = State{ .activation_epoch = 7, .roster_digest = @splat(2) };
    const other = State{ .mode = .active, .activation_epoch = 8, .roster_digest = @splat(2) };

    try testing.expect(permitsHandoff(default, staged));
    try testing.expect(!permitsHandoff(default, active));
    try testing.expect(!permitsHandoff(staged, default));
    try testing.expect(!permitsHandoff(staged, .{ .activation_epoch = 6, .roster_digest = @splat(2) }));
    try testing.expect(!permitsHandoff(staged, rebound));
    try testing.expect(permitsHandoff(staged, newer));
    try testing.expect(permitsHandoff(newer, other));
    try testing.expect(permitsHandoff(staged, active));
    try testing.expect(permitsHandoff(active, active));
    try testing.expect(!permitsHandoff(active, staged));
    try testing.expect(!permitsHandoff(active, other));
}

test "relay v2 activation roster digest is representation and order canonical" {
    const first: PublicKey = @splat(0x11);
    const second: PublicKey = @splat(0x22);
    const first_hex_lower = std.fmt.bytesToHex(first, .lower);
    const first_hex_upper = std.fmt.bytesToHex(first, .upper);
    var second_b64: [std.base64.standard.Encoder.calcSize(public_key_len)]u8 = undefined;
    const second_text = std.base64.standard.Encoder.encode(&second_b64, &second);

    var left = try canonicalizeRoster(testing.allocator, &.{ &first_hex_lower, second_text });
    defer left.deinit();
    var right = try canonicalizeRoster(testing.allocator, &.{ second_text, &first_hex_upper });
    defer right.deinit();
    try testing.expectEqualSlices(u8, &left.digest, &right.digest);
    try testing.expectEqualSlices(u8, &first, &left.keys[0]);
    try testing.expectEqualSlices(u8, &second, &left.keys[1]);

    const state_left = try stateFromConfig(testing.allocator, .compat, 9, &.{ &first_hex_lower, second_text });
    const state_right = try stateFromConfig(testing.allocator, .compat, 9, &.{ second_text, &first_hex_upper });
    try testing.expectEqual(state_left, state_right);
}

test "relay v2 activation roster rejects malformed duplicate incomplete and oversized inputs" {
    const key: PublicKey = @splat(0x33);
    const key_hex = std.fmt.bytesToHex(key, .lower);
    try testing.expectError(error.InvalidRoster, canonicalizeRoster(testing.allocator, &.{}));
    try testing.expectError(error.InvalidPublicKey, canonicalizeRoster(testing.allocator, &.{"aa"}));
    try testing.expectError(error.DuplicateRosterKey, canonicalizeRoster(testing.allocator, &.{ &key_hex, &key_hex }));
    try testing.expectError(error.IncompleteActivationPlan, stateFromConfig(testing.allocator, .compat, 7, &.{}));
    try testing.expectError(error.IncompleteActivationPlan, stateFromConfig(testing.allocator, .compat, 0, &.{&key_hex}));
    try testing.expectError(error.MissingActivationPlan, stateFromConfig(testing.allocator, .active, 0, &.{}));

    const too_many = try testing.allocator.alloc([]const u8, max_roster_entries + 1);
    defer testing.allocator.free(too_many);
    @memset(too_many, &key_hex);
    try testing.expectError(error.InvalidRoster, canonicalizeRoster(testing.allocator, too_many));
}

test "relay v2 activation binds configured identity to runtime full key" {
    const local: PublicKey = @splat(0x44);
    const other: PublicKey = @splat(0x45);
    const local_hex = std.fmt.bytesToHex(local, .lower);
    try testing.expectEqual(local, try bindConfiguredPublicKey(&local_hex, local));
    try testing.expectError(error.MissingLocalIdentity, bindConfiguredPublicKey(null, local));
    try testing.expectError(error.MissingLocalIdentity, bindConfiguredPublicKey(&local_hex, null));
    try testing.expectError(error.LocalIdentityMismatch, bindConfiguredPublicKey(&local_hex, other));
    try testing.expectError(error.InvalidPublicKey, bindConfiguredPublicKey("bad", local));
}

test "relay v2 activation roster construction survives every allocation failure" {
    const AllocationSweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const first = std.fmt.bytesToHex(@as(PublicKey, @splat(0x51)), .lower);
            const second = std.fmt.bytesToHex(@as(PublicKey, @splat(0x52)), .lower);
            var roster = try canonicalizeRoster(allocator, &.{ &second, &first });
            defer roster.deinit();
            try testing.expectEqual(@as(usize, 2), roster.keys.len);
            const state = try stateFromConfig(allocator, .active, 11, &.{ &first, &second });
            try testing.expectEqualSlices(u8, &roster.digest, &state.roster_digest);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, AllocationSweep.run, .{});
}
