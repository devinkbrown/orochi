//! In-memory write-ahead log and snapshot helpers for CRDT delta durability.
//!
//! The module deliberately avoids filesystem access. Callers own byte buffers,
//! pass them in, and receive owned slices for replay/recovery results.

const std = @import("std");

pub const frame_header_len = 8;

const snapshot_magic = "MIZWALS1";
const snapshot_version: u32 = 1;
const snapshot_header_len = snapshot_magic.len + 4 + 8 + 4 + 4;

pub const StopReason = enum {
    end,
    truncated,
    corrupt,
};

pub const AppendError = error{
    RecordTooLarge,
    OutOfMemory,
};

pub const SnapshotError = error{
    SnapshotTooLarge,
    InvalidSnapshot,
    SnapshotCrcMismatch,
    OutOfMemory,
};

pub const Frame = struct {
    offset: usize,
    next_offset: usize,
    payload: []const u8,
};

pub const ReplayResult = struct {
    records: [][]u8,
    valid_bytes: usize,
    stop_reason: StopReason,

    pub fn deinit(self: *ReplayResult, allocator: std.mem.Allocator) void {
        for (self.records) |record| allocator.free(record);
        allocator.free(self.records);
        self.* = .{
            .records = &[_][]u8{},
            .valid_bytes = 0,
            .stop_reason = .end,
        };
    }
};

pub const Snapshot = struct {
    blob: []u8,
    truncate_at: usize,

    pub fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.blob);
        self.* = .{
            .blob = &[_]u8{},
            .truncate_at = 0,
        };
    }
};

pub const DecodedSnapshot = struct {
    state: []u8,
    truncate_at: usize,

    pub fn deinit(self: *DecodedSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.state);
        self.* = .{
            .state = &[_]u8{},
            .truncate_at = 0,
        };
    }
};

pub const Recovery = struct {
    snapshot_state: []u8,
    records: [][]u8,
    latest_state: []u8,
    snapshot_truncate_at: usize,
    valid_tail_bytes: usize,
    stop_reason: StopReason,

    pub fn deinit(self: *Recovery, allocator: std.mem.Allocator) void {
        allocator.free(self.snapshot_state);
        for (self.records) |record| allocator.free(record);
        allocator.free(self.records);
        allocator.free(self.latest_state);
        self.* = .{
            .snapshot_state = &[_]u8{},
            .records = &[_][]u8{},
            .latest_state = &[_]u8{},
            .snapshot_truncate_at = 0,
            .valid_tail_bytes = 0,
            .stop_reason = .end,
        };
    }
};

pub const LogIterator = struct {
    log: []const u8,
    next_offset: usize = 0,
    valid_bytes: usize = 0,
    stop_reason: StopReason = .end,
    stopped: bool = false,

    pub fn init(log: []const u8) LogIterator {
        return .{ .log = log };
    }

    pub fn next(self: *LogIterator) ?Frame {
        if (self.stopped) return null;

        switch (parseFrame(self.log, self.next_offset)) {
            .frame => |frame| {
                self.next_offset = frame.next_offset;
                self.valid_bytes = frame.next_offset;
                return frame;
            },
            .stop => |reason| {
                self.stop_reason = reason;
                self.stopped = true;
                return null;
            },
        }
    }
};

const ParseResult = union(enum) {
    frame: Frame,
    stop: StopReason,
};

/// Append one framed record to `log` and return the record's starting offset.
pub fn append(
    allocator: std.mem.Allocator,
    log: *std.ArrayList(u8),
    record_bytes: []const u8,
) AppendError!usize {
    if (record_bytes.len > std.math.maxInt(u32)) return error.RecordTooLarge;

    const offset = log.items.len;
    var header: [frame_header_len]u8 = undefined;
    var pos: usize = 0;
    writeU32(&header, &pos, @intCast(record_bytes.len));
    writeU32(&header, &pos, crc32(record_bytes));

    errdefer log.items.len = offset;
    try log.appendSlice(allocator, &header);
    try log.appendSlice(allocator, record_bytes);
    return offset;
}

/// Replay valid records from the start of `log`.
///
/// The returned records are owned copies. Replay stops before the first
/// truncated or CRC-invalid frame and reports the reason plus valid prefix size.
pub fn replay(allocator: std.mem.Allocator, log: []const u8) !ReplayResult {
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |record| allocator.free(record);
        out.deinit(allocator);
    }

    var it = LogIterator.init(log);
    while (it.next()) |frame| {
        const copy = try allocator.dupe(u8, frame.payload);
        errdefer allocator.free(copy);
        try out.append(allocator, copy);
    }

    return .{
        .records = try out.toOwnedSlice(allocator),
        .valid_bytes = it.valid_bytes,
        .stop_reason = it.stop_reason,
    };
}

/// Encode a snapshot of the current CRDT state.
///
/// `truncate_at` is the log byte offset covered by the snapshot. After a
/// successful snapshot, callers may replay `log[truncate_at..]` during recovery.
pub fn snapshot(
    allocator: std.mem.Allocator,
    state_bytes: []const u8,
    truncate_at: usize,
) SnapshotError!Snapshot {
    if (state_bytes.len > std.math.maxInt(u32)) return error.SnapshotTooLarge;
    if (truncate_at > std.math.maxInt(u64)) return error.SnapshotTooLarge;

    const total_len = snapshot_header_len + state_bytes.len;
    const blob = try allocator.alloc(u8, total_len);
    errdefer allocator.free(blob);

    var pos: usize = 0;
    copyBytes(blob, &pos, snapshot_magic);
    writeU32(blob, &pos, snapshot_version);
    writeU64(blob, &pos, @intCast(truncate_at));
    writeU32(blob, &pos, @intCast(state_bytes.len));
    writeU32(blob, &pos, crc32(state_bytes));
    copyBytes(blob, &pos, state_bytes);

    return .{
        .blob = blob,
        .truncate_at = truncate_at,
    };
}

/// Decode and validate a snapshot blob, returning an owned state copy.
pub fn decodeSnapshot(
    allocator: std.mem.Allocator,
    blob: []const u8,
) SnapshotError!DecodedSnapshot {
    if (blob.len < snapshot_header_len) return error.InvalidSnapshot;
    if (!std.mem.eql(u8, blob[0..snapshot_magic.len], snapshot_magic)) {
        return error.InvalidSnapshot;
    }

    var pos: usize = snapshot_magic.len;
    const version = readU32(blob, &pos);
    if (version != snapshot_version) return error.InvalidSnapshot;

    const truncate_u64 = readU64(blob, &pos);
    if (truncate_u64 > std.math.maxInt(usize)) return error.InvalidSnapshot;
    const truncate_at: usize = @intCast(truncate_u64);

    const state_len_u32 = readU32(blob, &pos);
    const expected_crc = readU32(blob, &pos);
    const state_len: usize = state_len_u32;
    if (blob.len - snapshot_header_len != state_len) return error.InvalidSnapshot;

    const state_view = blob[pos .. pos + state_len];
    if (crc32(state_view) != expected_crc) return error.SnapshotCrcMismatch;

    return .{
        .state = try allocator.dupe(u8, state_view),
        .truncate_at = truncate_at,
    };
}

/// Recover from `snapshot_blob` and replay valid records from `log_tail`.
///
/// `snapshot_state` preserves the exact snapshot bytes. `records` contains
/// owned replayed post-snapshot records. `latest_state` is a convenience byte
/// reconstruction that appends valid record payloads to the snapshot state; CRDT
/// users that need semantic merge rules should apply `records` themselves.
pub fn recover(
    allocator: std.mem.Allocator,
    snapshot_blob: []const u8,
    log_tail: []const u8,
) !Recovery {
    var decoded = try decodeSnapshot(allocator, snapshot_blob);
    errdefer decoded.deinit(allocator);

    var replayed = try replay(allocator, log_tail);
    errdefer replayed.deinit(allocator);

    const latest = try concatStateAndRecords(allocator, decoded.state, replayed.records);
    errdefer allocator.free(latest);

    const result = Recovery{
        .snapshot_state = decoded.state,
        .records = replayed.records,
        .latest_state = latest,
        .snapshot_truncate_at = decoded.truncate_at,
        .valid_tail_bytes = replayed.valid_bytes,
        .stop_reason = replayed.stop_reason,
    };

    decoded.state = &[_]u8{};
    replayed.records = &[_][]u8{};
    return result;
}

/// Deterministic IEEE CRC-32 used for record and snapshot integrity.
pub fn crc32(bytes: []const u8) u32 {
    var crc: u32 = 0xffff_ffff;
    for (bytes) |byte| {
        crc ^= byte;
        var bit: u8 = 0;
        while (bit < 8) : (bit += 1) {
            const mask = @as(u32, 0) -% (crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    return ~crc;
}

fn parseFrame(log: []const u8, offset: usize) ParseResult {
    if (offset == log.len) return .{ .stop = .end };
    if (offset > log.len or log.len - offset < frame_header_len) {
        return .{ .stop = .truncated };
    }

    var pos = offset;
    const len_u32 = readU32(log, &pos);
    const expected_crc = readU32(log, &pos);
    const len: usize = len_u32;

    if (log.len - pos < len) return .{ .stop = .truncated };

    const end = pos + len;
    const payload = log[pos..end];
    if (crc32(payload) != expected_crc) return .{ .stop = .corrupt };

    return .{
        .frame = .{
            .offset = offset,
            .next_offset = end,
            .payload = payload,
        },
    };
}

fn concatStateAndRecords(
    allocator: std.mem.Allocator,
    state: []const u8,
    records: []const []u8,
) ![]u8 {
    var total = state.len;
    for (records) |record| {
        if (record.len > std.math.maxInt(usize) - total) return error.OutOfMemory;
        total += record.len;
    }

    const out = try allocator.alloc(u8, total);
    var pos: usize = 0;
    copyBytes(out, &pos, state);
    for (records) |record| copyBytes(out, &pos, record);
    return out;
}

fn copyBytes(out: []u8, pos: *usize, bytes: []const u8) void {
    @memcpy(out[pos.* .. pos.* + bytes.len], bytes);
    pos.* += bytes.len;
}

fn writeU32(out: []u8, pos: *usize, value: u32) void {
    out[pos.* + 0] = @intCast(value & 0xff);
    out[pos.* + 1] = @intCast((value >> 8) & 0xff);
    out[pos.* + 2] = @intCast((value >> 16) & 0xff);
    out[pos.* + 3] = @intCast((value >> 24) & 0xff);
    pos.* += 4;
}

fn writeU64(out: []u8, pos: *usize, value: u64) void {
    out[pos.* + 0] = @intCast(value & 0xff);
    out[pos.* + 1] = @intCast((value >> 8) & 0xff);
    out[pos.* + 2] = @intCast((value >> 16) & 0xff);
    out[pos.* + 3] = @intCast((value >> 24) & 0xff);
    out[pos.* + 4] = @intCast((value >> 32) & 0xff);
    out[pos.* + 5] = @intCast((value >> 40) & 0xff);
    out[pos.* + 6] = @intCast((value >> 48) & 0xff);
    out[pos.* + 7] = @intCast((value >> 56) & 0xff);
    pos.* += 8;
}

fn readU32(bytes: []const u8, pos: *usize) u32 {
    const value =
        @as(u32, bytes[pos.* + 0]) |
        (@as(u32, bytes[pos.* + 1]) << 8) |
        (@as(u32, bytes[pos.* + 2]) << 16) |
        (@as(u32, bytes[pos.* + 3]) << 24);
    pos.* += 4;
    return value;
}

fn readU64(bytes: []const u8, pos: *usize) u64 {
    const value =
        @as(u64, bytes[pos.* + 0]) |
        (@as(u64, bytes[pos.* + 1]) << 8) |
        (@as(u64, bytes[pos.* + 2]) << 16) |
        (@as(u64, bytes[pos.* + 3]) << 24) |
        (@as(u64, bytes[pos.* + 4]) << 32) |
        (@as(u64, bytes[pos.* + 5]) << 40) |
        (@as(u64, bytes[pos.* + 6]) << 48) |
        (@as(u64, bytes[pos.* + 7]) << 56);
    pos.* += 8;
    return value;
}

test "append then replay returns records in order" {
    const allocator = std.testing.allocator;
    var log: std.ArrayList(u8) = .empty;
    defer log.deinit(allocator);

    const off0 = try append(allocator, &log, "alpha");
    const off1 = try append(allocator, &log, "beta");
    const off2 = try append(allocator, &log, "gamma");

    try std.testing.expectEqual(@as(usize, 0), off0);
    try std.testing.expect(off1 > off0);
    try std.testing.expect(off2 > off1);

    var result = try replay(allocator, log.items);
    defer result.deinit(allocator);

    try std.testing.expectEqual(StopReason.end, result.stop_reason);
    try std.testing.expectEqual(log.items.len, result.valid_bytes);
    try std.testing.expectEqual(@as(usize, 3), result.records.len);
    try std.testing.expectEqualSlices(u8, "alpha", result.records[0]);
    try std.testing.expectEqualSlices(u8, "beta", result.records[1]);
    try std.testing.expectEqualSlices(u8, "gamma", result.records[2]);
}

test "corrupted record is detected by crc and replay stops before it" {
    const allocator = std.testing.allocator;
    var log: std.ArrayList(u8) = .empty;
    defer log.deinit(allocator);

    _ = try append(allocator, &log, "good");
    const valid_prefix = log.items.len;
    _ = try append(allocator, &log, "bad");
    _ = try append(allocator, &log, "after");

    log.items[valid_prefix + frame_header_len + 1] ^= 0x55;

    var result = try replay(allocator, log.items);
    defer result.deinit(allocator);

    try std.testing.expectEqual(StopReason.corrupt, result.stop_reason);
    try std.testing.expectEqual(valid_prefix, result.valid_bytes);
    try std.testing.expectEqual(@as(usize, 1), result.records.len);
    try std.testing.expectEqualSlices(u8, "good", result.records[0]);
}

test "truncated trailing record is ignored cleanly" {
    const allocator = std.testing.allocator;
    var log: std.ArrayList(u8) = .empty;
    defer log.deinit(allocator);

    _ = try append(allocator, &log, "stable");
    const valid_prefix = log.items.len;
    _ = try append(allocator, &log, "partial");
    log.items.len -= 2;

    var result = try replay(allocator, log.items);
    defer result.deinit(allocator);

    try std.testing.expectEqual(StopReason.truncated, result.stop_reason);
    try std.testing.expectEqual(valid_prefix, result.valid_bytes);
    try std.testing.expectEqual(@as(usize, 1), result.records.len);
    try std.testing.expectEqualSlices(u8, "stable", result.records[0]);
}

test "snapshot plus post snapshot replay reconstructs correctly" {
    const allocator = std.testing.allocator;
    var log: std.ArrayList(u8) = .empty;
    defer log.deinit(allocator);

    _ = try append(allocator, &log, "-pre1");
    _ = try append(allocator, &log, "-pre2");

    var snap = try snapshot(allocator, "base-pre1-pre2", log.items.len);
    defer snap.deinit(allocator);

    _ = try append(allocator, &log, "-post1");
    _ = try append(allocator, &log, "-post2");

    var recovered = try recover(allocator, snap.blob, log.items[snap.truncate_at..]);
    defer recovered.deinit(allocator);

    try std.testing.expectEqual(snap.truncate_at, recovered.snapshot_truncate_at);
    try std.testing.expectEqual(StopReason.end, recovered.stop_reason);
    try std.testing.expectEqual(log.items.len - snap.truncate_at, recovered.valid_tail_bytes);
    try std.testing.expectEqualSlices(u8, "base-pre1-pre2", recovered.snapshot_state);
    try std.testing.expectEqual(@as(usize, 2), recovered.records.len);
    try std.testing.expectEqualSlices(u8, "-post1", recovered.records[0]);
    try std.testing.expectEqualSlices(u8, "-post2", recovered.records[1]);
    try std.testing.expectEqualSlices(
        u8,
        "base-pre1-pre2-post1-post2",
        recovered.latest_state,
    );
}

test "empty log replays to no records" {
    const allocator = std.testing.allocator;

    var result = try replay(allocator, "");
    defer result.deinit(allocator);

    try std.testing.expectEqual(StopReason.end, result.stop_reason);
    try std.testing.expectEqual(@as(usize, 0), result.valid_bytes);
    try std.testing.expectEqual(@as(usize, 0), result.records.len);
}

test "deterministic crc" {
    try std.testing.expectEqual(@as(u32, 0xcbf4_3926), crc32("123456789"));
    try std.testing.expectEqual(crc32("same bytes"), crc32("same bytes"));
    try std.testing.expect(crc32("same bytes") != crc32("same bytez"));
}
