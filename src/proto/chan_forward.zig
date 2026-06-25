// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure channel-forwarding logic (the classic `+f` forward target).
//!
//! When a JOIN is refused by `+i`/`+l`/`+b`/`+k`/`+r`, a channel may be
//! configured to redirect the joining user to a forward channel. This module
//! owns the forward table and the chain-resolution logic that follows a
//! sequence of forwards while detecting self-forwards and multi-hop cycles.
//!
//! Comparison is ASCII case-insensitive (IRC channel names fold case). Keys are
//! stored lowercased so lookups are case-insensitive without per-lookup
//! allocation. No sockets, no filesystem, no clock reads.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Default ceiling on how many forward hops `resolveForward` will follow before
/// declaring a `.loop`. Callers may pass any positive value.
pub const DEFAULT_MAX_HOPS: usize = 16;

/// Minimum length of a channel name: a prefix char plus at least one char.
pub const MIN_CHANNEL_LEN: usize = 2;

/// Maximum accepted channel-name length (RFC-ish; daemon never exceeds this).
pub const MAX_CHANNEL_LEN: usize = 64;

/// Recognised channel-name prefixes.
const CHANNEL_PREFIXES = "#&";

/// Forward chain resolution outcome.
pub const Result = union(enum) {
    /// No forward is configured for `start` (or chain dead-ends with none).
    none,
    /// A reachable forward target after at least one hop. Slice borrows the
    /// table's owned value storage; valid until the table is mutated/freed.
    target: []const u8,
    /// A self-forward, multi-hop cycle, or a chain longer than `max_hops`.
    loop,
};

/// Allocator-backed forward table. Owns duped lowercased keys and duped
/// original-case values. Construct with `.empty`; release with `deinit`.
pub const ForwardMap = struct {
    entries: std.StringHashMapUnmanaged([]u8) = .empty,

    pub const empty: ForwardMap = .{};

    /// Free every owned key and value, then the backing table.
    pub fn deinit(self: *ForwardMap, allocator: Allocator) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.entries.deinit(allocator);
        self.* = .empty;
    }

    /// Number of configured forwards.
    pub fn count(self: *const ForwardMap) usize {
        return self.entries.count();
    }
};

/// Lowercase `src` into `dst` (ASCII fold). `dst.len` must be `>= src.len`.
fn foldInto(dst: []u8, src: []const u8) void {
    for (src, 0..) |c, i| dst[i] = std.ascii.toLower(c);
}

/// True when `name` looks like a usable channel name.
fn isChannelName(name: []const u8) bool {
    if (name.len < MIN_CHANNEL_LEN or name.len > MAX_CHANNEL_LEN) return false;
    if (std.mem.indexOfScalar(u8, CHANNEL_PREFIXES, name[0]) == null) return false;
    // Reject control chars, spaces, commas, and the bell — never valid in names.
    for (name) |c| {
        if (c <= ' ' or c == ',' or c == 7) return false;
    }
    return true;
}

/// Set or overwrite the forward for `from` -> `to`.
///
/// Keys are stored lowercased; values keep their original case. Overwriting an
/// existing entry frees the prior value (and reuses the existing key) so no
/// allocation leaks. On `error.OutOfMemory` the table is left unchanged.
pub fn setForward(
    map: *ForwardMap,
    allocator: Allocator,
    from: []const u8,
    to: []const u8,
) Allocator.Error!void {
    const key_buf = try allocator.alloc(u8, from.len);
    errdefer allocator.free(key_buf);
    foldInto(key_buf, from);

    const value = try allocator.dupe(u8, to);
    errdefer allocator.free(value);

    const gop = try map.entries.getOrPut(allocator, key_buf);
    if (gop.found_existing) {
        // Key already owned by the table; release our duplicate and the old value.
        allocator.free(key_buf);
        allocator.free(gop.value_ptr.*);
        gop.value_ptr.* = value;
    } else {
        gop.key_ptr.* = key_buf;
        gop.value_ptr.* = value;
    }
}

/// Look up the immediate forward target for `channel`, or `null` if none.
/// Returned slice borrows the table's owned storage.
pub fn getForward(map: *const ForwardMap, channel: []const u8) ?[]const u8 {
    if (channel.len == 0 or channel.len > MAX_CHANNEL_LEN) return null;
    var stack_buf: [MAX_CHANNEL_LEN]u8 = undefined;
    foldInto(stack_buf[0..channel.len], channel);
    const entry = map.entries.get(stack_buf[0..channel.len]) orelse return null;
    return entry;
}

/// Follow the forward chain starting at `start`.
///
/// Returns `.target` after at least one successful hop, `.none` if `start` has
/// no forward configured, or `.loop` if a self-forward, a cycle, or a chain
/// longer than `max_hops` is detected. The walk terminates without ever
/// re-visiting a folded channel name, so cycles cannot loop forever.
pub fn resolveForward(
    map: *const ForwardMap,
    start: []const u8,
    max_hops: usize,
) Result {
    if (max_hops == 0) return .none;

    var seen_buf: [MAX_CHANNEL_LEN]u8 = undefined;
    var current = start;
    var hops: usize = 0;

    while (true) {
        const next = getForward(map, current) orelse {
            return if (hops == 0) .none else .{ .target = current };
        };

        // A forward whose target folds to its own source is a self-loop.
        if (next.len == current.len) {
            foldInto(seen_buf[0..next.len], next);
            const folded_next = seen_buf[0..next.len];
            var folded_cur_buf: [MAX_CHANNEL_LEN]u8 = undefined;
            foldInto(folded_cur_buf[0..current.len], current);
            if (std.mem.eql(u8, folded_next, folded_cur_buf[0..current.len])) {
                return .loop;
            }
        }

        hops += 1;
        if (hops > max_hops) return .loop;

        // Detect a cycle back to the original start (handles A->B->A and longer).
        if (foldedEql(next, start)) return .loop;

        current = next;
    }
}

/// ASCII case-insensitive equality of two channel names.
fn foldedEql(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

/// True when `name` is acceptable as a forward target relative to `source`:
/// a valid channel name, within length bounds, and not equal (case-insensitive)
/// to the source channel.
pub fn validForwardTarget(name: []const u8, source: []const u8) bool {
    if (!isChannelName(name)) return false;
    if (foldedEql(name, source)) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "single hop A to B resolves to target B" {
    // Arrange
    const allocator = std.testing.allocator;
    var map: ForwardMap = .empty;
    defer map.deinit(allocator);
    try setForward(&map, allocator, "#a", "#b");

    // Act
    const result = resolveForward(&map, "#a", DEFAULT_MAX_HOPS);

    // Assert
    try std.testing.expect(result == .target);
    try std.testing.expectEqualStrings("#b", result.target);
}

test "no forward configured resolves to none" {
    // Arrange
    const allocator = std.testing.allocator;
    var map: ForwardMap = .empty;
    defer map.deinit(allocator);

    // Act
    const result = resolveForward(&map, "#lonely", DEFAULT_MAX_HOPS);

    // Assert
    try std.testing.expect(result == .none);
}

test "self forward A to A is detected as loop" {
    // Arrange
    const allocator = std.testing.allocator;
    var map: ForwardMap = .empty;
    defer map.deinit(allocator);
    try setForward(&map, allocator, "#self", "#self");

    // Act
    const result = resolveForward(&map, "#self", DEFAULT_MAX_HOPS);

    // Assert
    try std.testing.expect(result == .loop);
}

test "two cycle A to B to A is detected as loop" {
    // Arrange
    const allocator = std.testing.allocator;
    var map: ForwardMap = .empty;
    defer map.deinit(allocator);
    try setForward(&map, allocator, "#a", "#b");
    try setForward(&map, allocator, "#b", "#a");

    // Act
    const result = resolveForward(&map, "#a", DEFAULT_MAX_HOPS);

    // Assert
    try std.testing.expect(result == .loop);
}

test "chain exceeding max_hops resolves to loop" {
    // Arrange
    const allocator = std.testing.allocator;
    var map: ForwardMap = .empty;
    defer map.deinit(allocator);
    // #c0 -> #c1 -> #c2 -> #c3 -> #c4 (4 hops), all distinct, no cycle.
    try setForward(&map, allocator, "#c0", "#c1");
    try setForward(&map, allocator, "#c1", "#c2");
    try setForward(&map, allocator, "#c2", "#c3");
    try setForward(&map, allocator, "#c3", "#c4");

    // Act
    const limited = resolveForward(&map, "#c0", 2);
    const full = resolveForward(&map, "#c0", DEFAULT_MAX_HOPS);

    // Assert
    try std.testing.expect(limited == .loop);
    try std.testing.expect(full == .target);
    try std.testing.expectEqualStrings("#c4", full.target);
}

test "lookup is ascii case insensitive" {
    // Arrange
    const allocator = std.testing.allocator;
    var map: ForwardMap = .empty;
    defer map.deinit(allocator);
    try setForward(&map, allocator, "#Lobby", "#Overflow");

    // Act
    const direct = getForward(&map, "#lObBy");
    const resolved = resolveForward(&map, "#LOBBY", DEFAULT_MAX_HOPS);

    // Assert
    try std.testing.expect(direct != null);
    try std.testing.expectEqualStrings("#Overflow", direct.?);
    try std.testing.expect(resolved == .target);
    try std.testing.expectEqualStrings("#Overflow", resolved.target);
}

test "overwriting a forward frees old value without leaking" {
    // Arrange
    const allocator = std.testing.allocator;
    var map: ForwardMap = .empty;
    defer map.deinit(allocator);
    try setForward(&map, allocator, "#a", "#old");

    // Act
    try setForward(&map, allocator, "#A", "#new"); // same key, different case
    const result = getForward(&map, "#a");

    // Assert: count stays 1 and value is updated; allocator detects any leak.
    try std.testing.expectEqual(@as(usize, 1), map.count());
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("#new", result.?);
}

test "validForwardTarget rejects empty non-channel and self" {
    // Arrange / Act / Assert
    try std.testing.expect(!validForwardTarget("", "#a"));
    try std.testing.expect(!validForwardTarget("nochanprefix", "#a"));
    try std.testing.expect(!validForwardTarget("#", "#a")); // too short
    try std.testing.expect(!validForwardTarget("#has space", "#a"));
    try std.testing.expect(!validForwardTarget("#a", "#A")); // equals source (folded)
    try std.testing.expect(validForwardTarget("#overflow", "#main"));
    try std.testing.expect(validForwardTarget("&local", "#main"));
}

test "getForward returns null for unknown and oversized names" {
    // Arrange
    const allocator = std.testing.allocator;
    var map: ForwardMap = .empty;
    defer map.deinit(allocator);
    try setForward(&map, allocator, "#a", "#b");

    var huge: [MAX_CHANNEL_LEN + 4]u8 = undefined;
    @memset(&huge, 'x');
    huge[0] = '#';

    // Act / Assert
    try std.testing.expect(getForward(&map, "#missing") == null);
    try std.testing.expect(getForward(&map, "") == null);
    try std.testing.expect(getForward(&map, &huge) == null);
}
