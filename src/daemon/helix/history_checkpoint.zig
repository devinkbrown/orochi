// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Helix payload for the complete CHATHISTORY projection.
//!
//! One fixed-shape record carries the Lotus message rings (`LTHC`), the
//! SearchIndex projection (`SIDX`), and node EventHistory (`OEH1`). Decoding is
//! allocation-free and returns slices borrowed from the authenticated input so
//! a successor can stage all three inner stores before publishing any of them.
const std = @import("std");

const Blake3 = std.crypto.hash.Blake3;

const magic = "OHCP";
const version: u8 = 1;
const component_count: u8 = 3;
const header_len: usize = 24;
const checksum_len: usize = Blake3.digest_length;
const lotus_magic = "LTHC";
const search_index_magic = "SIDX";
const event_history_magic = "OEH1";
const lotus_min_len: usize = 52 + Blake3.digest_length;
const search_index_min_len: usize = 29 + Blake3.digest_length;
const event_history_min_len: usize = 4 + 1 + 4;

pub const Config = struct {
    max_lotus_bytes: usize = 64 * 1024 * 1024,
    max_search_index_bytes: usize = 64 * 1024 * 1024,
    max_event_history_bytes: usize = 8 * 1024 * 1024,
    max_checkpoint_bytes: usize = 136 * 1024 * 1024 + header_len + checksum_len,
};

pub const Payloads = struct {
    lotus: []const u8,
    search_index: []const u8,
    event_history: []const u8,
};

/// All slices borrow the checkpoint byte buffer passed to `decode`.
pub const BorrowedPayloads = Payloads;

pub const Error = std.mem.Allocator.Error || error{
    BadMagic,
    UnsupportedVersion,
    ComponentCountMismatch,
    InvalidHeader,
    InvalidConfig,
    MissingComponent,
    WrongComponent,
    CapacityExceeded,
    CheckpointTooLarge,
    Truncated,
    TrailingBytes,
    LengthMismatch,
    ChecksumMismatch,
};

/// Package three already-encoded exact checkpoints into one owned Helix
/// History payload. Inner payload discriminants are checked before allocation.
pub fn encode(
    allocator: std.mem.Allocator,
    cfg: Config,
    payloads: Payloads,
) Error![]u8 {
    try validateConfig(cfg);
    try validatePayloads(cfg, payloads);

    var body_len: usize = 0;
    body_len = try addBounded(body_len, payloads.lotus.len, cfg.max_checkpoint_bytes);
    body_len = try addBounded(body_len, payloads.search_index.len, cfg.max_checkpoint_bytes);
    body_len = try addBounded(body_len, payloads.event_history.len, cfg.max_checkpoint_bytes);
    const prefix_len = try addBounded(header_len, body_len, cfg.max_checkpoint_bytes);
    const total_len = try addBounded(prefix_len, checksum_len, cfg.max_checkpoint_bytes);

    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);
    @memcpy(out[0..4], magic);
    out[4] = version;
    out[5] = component_count;
    writeU16(out[6..8], 0);
    writeU32(out[8..12], @intCast(payloads.lotus.len));
    writeU32(out[12..16], @intCast(payloads.search_index.len));
    writeU32(out[16..20], @intCast(payloads.event_history.len));
    writeU32(out[20..24], @intCast(body_len));

    var pos = header_len;
    for ([_][]const u8{ payloads.lotus, payloads.search_index, payloads.event_history }) |payload| {
        @memcpy(out[pos..][0..payload.len], payload);
        pos += payload.len;
    }
    std.debug.assert(pos == prefix_len);
    checkpointChecksum(out[0..prefix_len], out[prefix_len..][0..checksum_len]);
    return out;
}

/// Authenticate and split one complete History payload. No allocation occurs;
/// returned slices remain valid exactly as long as `bytes` remains valid.
pub fn decode(cfg: Config, bytes: []const u8) Error!BorrowedPayloads {
    try validateConfig(cfg);
    if (bytes.len > cfg.max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < header_len + checksum_len) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..4], magic)) return error.BadMagic;
    if (bytes[4] != version) return error.UnsupportedVersion;
    if (bytes[5] != component_count) return error.ComponentCountMismatch;
    if (readU16(bytes[6..8]) != 0) return error.InvalidHeader;

    const lotus_len: usize = readU32(bytes[8..12]);
    const search_index_len: usize = readU32(bytes[12..16]);
    const event_history_len: usize = readU32(bytes[16..20]);
    const declared_body_len: usize = readU32(bytes[20..24]);
    if (lotus_len > cfg.max_lotus_bytes or
        search_index_len > cfg.max_search_index_bytes or
        event_history_len > cfg.max_event_history_bytes)
        return error.CapacityExceeded;

    var computed_body_len: usize = 0;
    computed_body_len = try addBounded(computed_body_len, lotus_len, cfg.max_checkpoint_bytes);
    computed_body_len = try addBounded(computed_body_len, search_index_len, cfg.max_checkpoint_bytes);
    computed_body_len = try addBounded(computed_body_len, event_history_len, cfg.max_checkpoint_bytes);
    if (computed_body_len != declared_body_len) return error.LengthMismatch;
    const prefix_len = try addBounded(header_len, declared_body_len, cfg.max_checkpoint_bytes);
    const expected_len = try addBounded(prefix_len, checksum_len, cfg.max_checkpoint_bytes);
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;

    var checksum: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0..prefix_len], &checksum);
    if (!std.mem.eql(u8, &checksum, bytes[prefix_len..])) return error.ChecksumMismatch;

    var pos = header_len;
    const lotus = bytes[pos..][0..lotus_len];
    pos += lotus_len;
    const search_index = bytes[pos..][0..search_index_len];
    pos += search_index_len;
    const event_history = bytes[pos..][0..event_history_len];
    pos += event_history_len;
    std.debug.assert(pos == prefix_len);
    const payloads = Payloads{
        .lotus = lotus,
        .search_index = search_index,
        .event_history = event_history,
    };
    try validatePayloads(cfg, payloads);
    return payloads;
}

fn validateConfig(cfg: Config) Error!void {
    if (cfg.max_lotus_bytes < lotus_min_len or
        cfg.max_search_index_bytes < search_index_min_len or
        cfg.max_event_history_bytes < event_history_min_len)
        return error.InvalidConfig;
    for ([_]usize{ cfg.max_lotus_bytes, cfg.max_search_index_bytes, cfg.max_event_history_bytes }) |limit| {
        if (limit > std.math.maxInt(u32)) return error.InvalidConfig;
    }
    var minimum_len: usize = header_len;
    minimum_len = std.math.add(usize, minimum_len, lotus_min_len) catch return error.InvalidConfig;
    minimum_len = std.math.add(usize, minimum_len, search_index_min_len) catch return error.InvalidConfig;
    minimum_len = std.math.add(usize, minimum_len, event_history_min_len) catch return error.InvalidConfig;
    minimum_len = std.math.add(usize, minimum_len, checksum_len) catch return error.InvalidConfig;
    if (cfg.max_checkpoint_bytes < minimum_len) return error.InvalidConfig;
}

fn validatePayloads(cfg: Config, payloads: Payloads) Error!void {
    try validatePayload(payloads.lotus, lotus_magic, lotus_min_len, cfg.max_lotus_bytes);
    try validatePayload(payloads.search_index, search_index_magic, search_index_min_len, cfg.max_search_index_bytes);
    try validatePayload(payloads.event_history, event_history_magic, event_history_min_len, cfg.max_event_history_bytes);
}

fn validatePayload(payload: []const u8, expected_magic: *const [4:0]u8, minimum_len: usize, maximum_len: usize) Error!void {
    if (payload.len == 0) return error.MissingComponent;
    if (payload.len < minimum_len) return error.MissingComponent;
    if (payload.len > maximum_len) return error.CapacityExceeded;
    if (!std.mem.eql(u8, payload[0..4], expected_magic[0..4])) return error.WrongComponent;
}

fn addBounded(a: usize, b: usize, maximum: usize) Error!usize {
    const sum = std.math.add(usize, a, b) catch return error.CheckpointTooLarge;
    if (sum > maximum or sum > std.math.maxInt(u32)) return error.CheckpointTooLarge;
    return sum;
}

fn checkpointChecksum(prefix: []const u8, out: *[checksum_len]u8) void {
    var hasher = Blake3.init(.{});
    hasher.update("onyx_server.history.checkpoint.v1");
    hasher.update(prefix);
    hasher.final(out);
}

fn rewriteChecksum(bytes: []u8) void {
    if (bytes.len < checksum_len) return;
    const prefix_len = bytes.len - checksum_len;
    checkpointChecksum(bytes[0..prefix_len], bytes[prefix_len..][0..checksum_len]);
}

fn writeU16(out: []u8, value: u16) void {
    std.mem.writeInt(u16, out[0..2], value, .big);
}

fn writeU32(out: []u8, value: u32) void {
    std.mem.writeInt(u32, out[0..4], value, .big);
}

fn readU16(bytes: []const u8) u16 {
    return std.mem.readInt(u16, bytes[0..2], .big);
}

fn readU32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .big);
}

test "history checkpoint round trips exact independently decodable payloads" {
    const lotus_mod = @import("../../proto/lotus.zig");
    const search_mod = @import("../search_index.zig");
    const event_mod = @import("../event_history.zig");
    const testing = std.testing;
    const cfg = Config{
        .max_lotus_bytes = 4096,
        .max_search_index_bytes = 4096,
        .max_event_history_bytes = 4096,
        .max_checkpoint_bytes = 16 * 1024,
    };

    const Lotus = lotus_mod.Lotus(.{
        .max_targets = 2,
        .max_per_target = 4,
        .max_text = 64,
        .max_target = 16,
        .max_msgid = 16,
        .max_sender = 16,
        .max_command = 16,
        .max_client_tags = 64,
        .max_checkpoint_bytes = 4096,
    });
    var lotus = Lotus.init(testing.allocator);
    defer lotus.deinit();
    _ = try lotus.append("#a", .{ .msgid = "m1", .sender = "alice", .text = "hello history", .timestamp = 1 });
    _ = try lotus.append("#a", .{ .msgid = "m2", .sender = "alice", .text = "", .timestamp = 2, .command = "TAGMSG", .client_tags = "+x=1" });
    const lotus_wire = try lotus.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(lotus_wire);

    const search_cfg = search_mod.SearchIndex.Config{
        .max_words = 16,
        .max_ids_per_word = 8,
        .max_token_bytes = 16,
        .max_id_bytes = 16,
        .max_checkpoint_bytes = 4096,
    };
    var search = search_mod.SearchIndex.initWithConfig(testing.allocator, search_cfg);
    defer search.deinit();
    try search.index("m1", "hello history");
    const search_wire = try search.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(search_wire);

    var events = event_mod.EventHistory(4){};
    events.record(1, 2, 3, "node.test", "history restored");
    var event_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer event_writer.deinit();
    try events.serializeInto(&event_writer.writer);

    const wire = try encode(testing.allocator, cfg, .{
        .lotus = lotus_wire,
        .search_index = search_wire,
        .event_history = event_writer.written(),
    });
    defer testing.allocator.free(wire);
    const decoded = try decode(cfg, wire);
    try testing.expectEqualSlices(u8, lotus_wire, decoded.lotus);
    try testing.expectEqualSlices(u8, search_wire, decoded.search_index);
    try testing.expectEqualSlices(u8, event_writer.written(), decoded.event_history);

    var restored_lotus = try Lotus.decodeCheckpoint(testing.allocator, decoded.lotus);
    defer restored_lotus.deinit();
    try testing.expectEqual(@as(usize, 2), restored_lotus.totalStoredCount());
    var restored_search = try search_mod.SearchIndex.decodeCheckpoint(testing.allocator, search_cfg, decoded.search_index);
    defer restored_search.deinit();
    try testing.expectEqualStrings("m1", restored_search.find("history")[0]);
    const event_replacement = event_mod.EventHistory(4).restoreHelixCheckpoint(decoded.event_history) orelse
        return error.TestUnexpectedResult;
    var restored_events = event_mod.EventHistory(4){};
    restored_events.publishCheckpoint(&event_replacement);
    try testing.expectEqual(@as(usize, 1), restored_events.len());

    const wire_again = try encode(testing.allocator, cfg, decoded);
    defer testing.allocator.free(wire_again);
    try testing.expectEqualSlices(u8, wire, wire_again);
}

test "history checkpoint rejects missing extra corrupt length checksum and trailing data" {
    const testing = std.testing;
    const cfg = Config{
        .max_lotus_bytes = 256,
        .max_search_index_bytes = 256,
        .max_event_history_bytes = 256,
        .max_checkpoint_bytes = 1024,
    };
    var lotus: [lotus_min_len]u8 = @splat(0);
    @memcpy(lotus[0..4], lotus_magic);
    var search_index: [search_index_min_len]u8 = @splat(0);
    @memcpy(search_index[0..4], search_index_magic);
    var event_history: [event_history_min_len]u8 = @splat(0);
    @memcpy(event_history[0..4], event_history_magic);
    const wire = try encode(testing.allocator, cfg, .{
        .lotus = &lotus,
        .search_index = &search_index,
        .event_history = &event_history,
    });
    defer testing.allocator.free(wire);

    for (0..wire.len) |len| {
        try testing.expectError(error.Truncated, decode(cfg, wire[0..len]));
    }

    const trailing = try testing.allocator.alloc(u8, wire.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try testing.expectError(error.TrailingBytes, decode(cfg, trailing));

    const bad_magic = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(bad_magic);
    bad_magic[0] ^= 1;
    try testing.expectError(error.BadMagic, decode(cfg, bad_magic));

    const bad_version = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(bad_version);
    bad_version[4] +%= 1;
    rewriteChecksum(bad_version);
    try testing.expectError(error.UnsupportedVersion, decode(cfg, bad_version));

    for ([_]u8{ 2, 4 }) |count| {
        const wrong_count = try testing.allocator.dupe(u8, wire);
        defer testing.allocator.free(wrong_count);
        wrong_count[5] = count;
        rewriteChecksum(wrong_count);
        try testing.expectError(error.ComponentCountMismatch, decode(cfg, wrong_count));
    }

    const reserved = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(reserved);
    reserved[7] = 1;
    rewriteChecksum(reserved);
    try testing.expectError(error.InvalidHeader, decode(cfg, reserved));

    const corrupt_length = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(corrupt_length);
    writeU32(corrupt_length[8..12], readU32(corrupt_length[8..12]) + 1);
    rewriteChecksum(corrupt_length);
    try testing.expectError(error.LengthMismatch, decode(cfg, corrupt_length));

    const missing = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(missing);
    writeU32(missing[8..12], 0);
    writeU32(missing[20..24], readU32(missing[20..24]) - @as(u32, @intCast(lotus_min_len)));
    // The physical bytes deliberately remain: exact outer framing rejects them.
    rewriteChecksum(missing);
    try testing.expectError(error.TrailingBytes, decode(cfg, missing));

    const wrong_component = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(wrong_component);
    @memcpy(wrong_component[header_len..][0..4], search_index_magic);
    rewriteChecksum(wrong_component);
    try testing.expectError(error.WrongComponent, decode(cfg, wrong_component));

    const bad_checksum = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(bad_checksum);
    bad_checksum[header_len + 4] ^= 1;
    try testing.expectError(error.ChecksumMismatch, decode(cfg, bad_checksum));

    const too_small = Config{
        .max_lotus_bytes = lotus_min_len,
        .max_search_index_bytes = search_index_min_len,
        .max_event_history_bytes = event_history_min_len,
        .max_checkpoint_bytes = header_len + checksum_len + lotus_min_len + search_index_min_len + event_history_min_len - 1,
    };
    try testing.expectError(error.InvalidConfig, decode(too_small, wire));
}

test "history checkpoint encode is leak free across every allocation failure" {
    const testing = std.testing;
    const cfg = Config{
        .max_lotus_bytes = 256,
        .max_search_index_bytes = 256,
        .max_event_history_bytes = 256,
        .max_checkpoint_bytes = 1024,
    };
    var lotus: [lotus_min_len]u8 = @splat(0);
    @memcpy(lotus[0..4], lotus_magic);
    var search_index: [search_index_min_len]u8 = @splat(0);
    @memcpy(search_index[0..4], search_index_magic);
    var event_history: [event_history_min_len]u8 = @splat(0);
    @memcpy(event_history[0..4], event_history_magic);
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, config: Config, payloads: Payloads) !void {
            const wire = try encode(allocator, config, payloads);
            defer allocator.free(wire);
            const decoded = try decode(config, wire);
            try testing.expectEqualSlices(u8, payloads.lotus, decoded.lotus);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ cfg, Payloads{
        .lotus = &lotus,
        .search_index = &search_index,
        .event_history = &event_history,
    } });
}

test "history component staging is leak free across every allocation failure" {
    const lotus_mod = @import("../../proto/lotus.zig");
    const search_mod = @import("../search_index.zig");
    const event_mod = @import("../event_history.zig");
    const testing = std.testing;
    const cfg = Config{
        .max_lotus_bytes = 4096,
        .max_search_index_bytes = 4096,
        .max_event_history_bytes = 4096,
        .max_checkpoint_bytes = 16 * 1024,
    };
    const Lotus = lotus_mod.Lotus(.{
        .max_targets = 2,
        .max_per_target = 3,
        .max_text = 64,
        .max_target = 16,
        .max_msgid = 16,
        .max_sender = 16,
        .max_command = 16,
        .max_client_tags = 64,
        .max_checkpoint_bytes = 4096,
    });
    const search_cfg = search_mod.SearchIndex.Config{
        .max_words = 16,
        .max_ids_per_word = 8,
        .max_token_bytes = 16,
        .max_id_bytes = 16,
        .max_checkpoint_bytes = 4096,
    };
    const History = event_mod.EventHistory(2);

    var lotus = Lotus.init(testing.allocator);
    defer lotus.deinit();
    _ = try lotus.append("#a", .{ .msgid = "m1", .sender = "alice", .text = "hello", .timestamp = 1 });
    const lotus_wire = try lotus.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(lotus_wire);
    var search = search_mod.SearchIndex.initWithConfig(testing.allocator, search_cfg);
    defer search.deinit();
    try search.index("m1", "hello");
    const search_wire = try search.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(search_wire);
    var events = History{};
    events.record(1, 2, 3, "node", "event");
    var event_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer event_writer.deinit();
    try events.serializeInto(&event_writer.writer);
    const wire = try encode(testing.allocator, cfg, .{
        .lotus = lotus_wire,
        .search_index = search_wire,
        .event_history = event_writer.written(),
    });
    defer testing.allocator.free(wire);

    const Sweep = struct {
        fn run(
            allocator: std.mem.Allocator,
            config: Config,
            search_config: search_mod.SearchIndex.Config,
            bytes: []const u8,
        ) !void {
            const payloads = try decode(config, bytes);
            var lotus_candidate = try Lotus.decodeCheckpoint(allocator, payloads.lotus);
            defer lotus_candidate.deinit();
            var search_candidate = try search_mod.SearchIndex.decodeCheckpoint(
                allocator,
                search_config,
                payloads.search_index,
            );
            defer search_candidate.deinit();
            const event_candidate = History.restoreHelixCheckpoint(payloads.event_history) orelse
                return error.InvalidEventHistory;
            try testing.expectEqual(@as(usize, 1), lotus_candidate.totalStoredCount());
            try testing.expectEqualStrings("m1", search_candidate.find("hello")[0]);
            try testing.expectEqual(@as(usize, 1), event_candidate.count);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ cfg, search_cfg, wire });
}

test "history transaction rejects late malformed or lossy components without publication" {
    const lotus_mod = @import("../../proto/lotus.zig");
    const search_mod = @import("../search_index.zig");
    const event_mod = @import("../event_history.zig");
    const testing = std.testing;
    const cfg = Config{
        .max_lotus_bytes = 4096,
        .max_search_index_bytes = 4096,
        .max_event_history_bytes = 4096,
        .max_checkpoint_bytes = 16 * 1024,
    };
    const Lotus = lotus_mod.Lotus(.{
        .max_targets = 2,
        .max_per_target = 3,
        .max_text = 64,
        .max_target = 16,
        .max_msgid = 16,
        .max_sender = 16,
        .max_command = 16,
        .max_client_tags = 64,
        .max_checkpoint_bytes = 4096,
    });
    const search_cfg = search_mod.SearchIndex.Config{
        .max_words = 16,
        .max_ids_per_word = 8,
        .max_token_bytes = 16,
        .max_id_bytes = 16,
        .max_checkpoint_bytes = 4096,
    };
    const History = event_mod.EventHistory(2);

    var source_lotus = Lotus.init(testing.allocator);
    defer source_lotus.deinit();
    _ = try source_lotus.append("#new", .{ .msgid = "new", .sender = "alice", .text = "new body", .timestamp = 1 });
    const source_lotus_root = source_lotus.root();
    const lotus_wire = try source_lotus.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(lotus_wire);
    var source_search = search_mod.SearchIndex.initWithConfig(testing.allocator, search_cfg);
    defer source_search.deinit();
    try source_search.index("new", "alpha");
    const search_wire = try source_search.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(search_wire);
    var source_events = History{};
    source_events.record(1, 2, 3, "new", "new event");
    var event_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer event_writer.deinit();
    try source_events.serializeInto(&event_writer.writer);

    var live_lotus = Lotus.init(testing.allocator);
    defer live_lotus.deinit();
    _ = try live_lotus.append("#old", .{ .msgid = "old", .sender = "sentinel", .text = "keep", .timestamp = 9 });
    const old_lotus_root = live_lotus.root();
    var live_search = search_mod.SearchIndex.initWithConfig(testing.allocator, search_cfg);
    defer live_search.deinit();
    try live_search.index("old", "sentinel");
    var live_events = History{};
    live_events.record(9, 9, 9, "old", "sentinel event");

    const Apply = struct {
        fn run(
            lotus_target: *Lotus,
            search_target: *search_mod.SearchIndex,
            event_target: *History,
            config: Config,
            search_config: search_mod.SearchIndex.Config,
            bytes: []const u8,
        ) !void {
            const payloads = try decode(config, bytes);
            var lotus_candidate = try Lotus.decodeCheckpoint(lotus_target.allocator, payloads.lotus);
            errdefer lotus_candidate.deinit();
            var search_candidate = try search_mod.SearchIndex.decodeCheckpoint(
                search_target.allocator,
                search_config,
                payloads.search_index,
            );
            errdefer search_candidate.deinit();
            const event_candidate = History.restoreHelixCheckpoint(payloads.event_history) orelse
                return error.InvalidEventHistory;

            std.mem.swap(Lotus, lotus_target, &lotus_candidate);
            std.mem.swap(search_mod.SearchIndex, search_target, &search_candidate);
            event_target.publishCheckpoint(&event_candidate);
            lotus_candidate.deinit();
            search_candidate.deinit();
        }
    };

    const corrupt_search = try testing.allocator.dupe(u8, search_wire);
    defer testing.allocator.free(corrupt_search);
    corrupt_search[corrupt_search.len - 1] ^= 1;
    const malformed_bundle = try encode(testing.allocator, cfg, .{
        .lotus = lotus_wire,
        .search_index = corrupt_search,
        .event_history = event_writer.written(),
    });
    defer testing.allocator.free(malformed_bundle);
    try testing.expectError(
        error.ChecksumMismatch,
        Apply.run(&live_lotus, &live_search, &live_events, cfg, search_cfg, malformed_bundle),
    );
    const after_malformed_lotus_root = live_lotus.root();
    try testing.expectEqualSlices(u8, &old_lotus_root, &after_malformed_lotus_root);
    try testing.expectEqualStrings("old", live_search.find("sentinel")[0]);
    var event_out: [2]event_mod.StoredEvent = undefined;
    try testing.expectEqual(@as(usize, 1), live_events.collect(null, 0, &event_out));
    try testing.expectEqualStrings("sentinel event", event_out[0].message());

    var large_events = event_mod.EventHistory(3){};
    large_events.record(1, 1, 1, "large", "one");
    large_events.record(2, 1, 2, "large", "two");
    large_events.record(3, 1, 3, "large", "three");
    var large_event_writer = std.Io.Writer.Allocating.init(testing.allocator);
    defer large_event_writer.deinit();
    try large_events.serializeInto(&large_event_writer.writer);
    const lossy_bundle = try encode(testing.allocator, cfg, .{
        .lotus = lotus_wire,
        .search_index = search_wire,
        .event_history = large_event_writer.written(),
    });
    defer testing.allocator.free(lossy_bundle);
    try testing.expectError(
        error.InvalidEventHistory,
        Apply.run(&live_lotus, &live_search, &live_events, cfg, search_cfg, lossy_bundle),
    );
    const after_lossy_lotus_root = live_lotus.root();
    try testing.expectEqualSlices(u8, &old_lotus_root, &after_lossy_lotus_root);
    try testing.expectEqualStrings("old", live_search.find("sentinel")[0]);
    try testing.expectEqual(@as(usize, 1), live_events.collect(null, 0, &event_out));
    try testing.expectEqualStrings("sentinel event", event_out[0].message());

    const valid_bundle = try encode(testing.allocator, cfg, .{
        .lotus = lotus_wire,
        .search_index = search_wire,
        .event_history = event_writer.written(),
    });
    defer testing.allocator.free(valid_bundle);
    try Apply.run(&live_lotus, &live_search, &live_events, cfg, search_cfg, valid_bundle);
    const restored_lotus_root = live_lotus.root();
    try testing.expectEqualSlices(u8, &source_lotus_root, &restored_lotus_root);
    try testing.expectEqualStrings("new", live_search.find("alpha")[0]);
    try testing.expectEqual(@as(usize, 1), live_events.collect(null, 0, &event_out));
    try testing.expectEqualStrings("new event", event_out[0].message());
}
