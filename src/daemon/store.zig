//! OroStore embedded persistence skeleton.
//!
//! This is intentionally small, Zig-native, and standalone: an in-memory typed
//! key/value store backed by a checksummed append-only log, with snapshot
//! compaction and a bounded recent-mutation feed for service sync.
const std = @import("std");
const toml = @import("../proto/toml.zig");

const record_header_len = 8;
const payload_header_len = 10;
const default_max_record_len = 16 * 1024 * 1024;
const default_max_wal_len = 256 * 1024 * 1024;
const default_changefeed_capacity = 64;
const tombstone_len = std.math.maxInt(u32);
const meta_kind_next_seq: u8 = 0xFE;
const meta_next_seq_payload_len = 9;

pub const StoreError = error{
    BadRecord,
    ChecksumMismatch,
    UnknownFamily,
    UnknownRecordKind,
    RecordTooLarge,
};

/// Runtime-tunable storage limits. Defaults preserve the historical hardcoded
/// behaviour; the orchestrator overlays the `[storage]` TOML section via
/// `Config.applyToml` before opening the store.
pub const Config = struct {
    /// Max single WAL/snapshot record payload size (bytes).
    max_record_bytes: usize = default_max_record_len,
    /// Max WAL file size accepted on replay (bytes); oversize logs are rejected.
    max_wal_bytes: usize = default_max_wal_len,
    /// Bounded recent-mutation changefeed ring size (entries).
    changefeed_capacity: usize = default_changefeed_capacity,

    /// Overlay `[storage]` keys from a parsed TOML document onto `cfg`. Missing
    /// keys leave the current value untouched. Pure: no I/O, never fails.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("storage.max_record_bytes")) |v| {
            if (v >= 1 and v <= std.math.maxInt(u32)) cfg.max_record_bytes = @intCast(v);
        }
        if (doc.getUint("storage.max_wal_bytes")) |v| {
            if (v >= 1) cfg.max_wal_bytes = @intCast(v);
        }
        if (doc.getUint("storage.changefeed_capacity")) |v| {
            if (v >= 1) cfg.changefeed_capacity = @intCast(v);
        }
    }
};

pub const Family = enum(u8) {
    accounts,
    nicks,
    chanregs,
    bans,
    memos,
    vhosts,
    props,
    history,
};

pub const MutationKind = enum(u8) {
    put,
    delete,
};

pub const Mutation = struct {
    seq: u64,
    family: Family,
    kind: MutationKind,
    key: []const u8,
    value: ?[]const u8,
};

pub fn ColumnFamily(comptime store_family: Family) type {
    return struct {
        store: *OroStore,

        pub fn put(self: @This(), key: []const u8, value: []const u8) !void {
            try self.store.put(store_family, key, value);
        }

        pub fn get(self: @This(), key: []const u8) ?[]const u8 {
            return self.store.get(store_family, key);
        }

        pub fn delete(self: @This(), key: []const u8) !void {
            try self.store.delete(store_family, key);
        }
    };
}

pub const OroStore = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    wal_path: []u8,
    snapshot_path: []u8,
    wal_file: ?std.Io.File = null,
    wal_offset: u64 = 0,
    maps: [family_count]KvMap,
    changefeed: ChangeFeed,
    next_seq: u64 = 1,
    cfg: Config = .{},

    /// Opens `wal_path` under `dir`, replays `<wal_path>.snap` first, then WAL.
    pub fn open(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        wal_path: []const u8,
    ) !OroStore {
        return openWithConfig(allocator, io, dir, wal_path, .{});
    }

    /// Like `open`, but with explicit storage limits (see `Config`).
    pub fn openWithConfig(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        wal_path: []const u8,
        cfg: Config,
    ) !OroStore {
        const owned_wal = try allocator.dupe(u8, wal_path);
        const owned_snapshot = std.mem.concat(allocator, u8, &.{ wal_path, ".snap" }) catch |err| {
            allocator.free(owned_wal);
            return err;
        };

        var store = OroStore{
            .allocator = allocator,
            .io = io,
            .dir = dir,
            .wal_path = owned_wal,
            .snapshot_path = owned_snapshot,
            .maps = initMaps(allocator),
            .changefeed = try ChangeFeed.init(allocator, cfg.changefeed_capacity),
            .cfg = cfg,
        };
        errdefer store.deinit();

        try store.replayFile(store.snapshot_path, .snapshot);
        try store.replayFile(store.wal_path, .wal);
        try store.ensureWal();
        return store;
    }

    pub fn deinit(self: *OroStore) void {
        if (self.wal_file) |file| file.close(self.io);
        for (&self.maps) |*map| map.deinit();
        self.changefeed.deinit();
        self.allocator.free(self.wal_path);
        self.allocator.free(self.snapshot_path);
        self.* = undefined;
    }

    /// Returns the comptime-typed API for one column family.
    pub fn family(self: *OroStore, comptime store_family: Family) ColumnFamily(store_family) {
        return .{ .store = self };
    }

    pub fn put(self: *OroStore, store_family: Family, key: []const u8, value: []const u8) !void {
        try self.appendRecord(.put, store_family, key, value);
        try self.applyPut(store_family, key, value);
        try self.recordMutation(store_family, .put, key, value);
    }

    pub fn get(self: *const OroStore, store_family: Family, key: []const u8) ?[]const u8 {
        return self.maps[familyIndex(store_family)].get(key);
    }

    pub fn delete(self: *OroStore, store_family: Family, key: []const u8) !void {
        try self.appendRecord(.delete, store_family, key, "");
        try self.applyDelete(store_family, key);
        try self.recordMutation(store_family, .delete, key, null);
    }

    /// Writes current state to a snapshot and truncates the WAL.
    pub fn snapshotAndTruncate(self: *OroStore) !void {
        var snapshot = try self.dir.createFileAtomic(self.io, self.snapshot_path, .{ .replace = true });
        defer snapshot.deinit(self.io);

        var offset: u64 = 0;
        offset = try writeNextSeqRecordAt(self.io, snapshot.file, offset, self.allocator, self.next_seq);
        for (families) |store_family| {
            var it = self.maps[familyIndex(store_family)].map.iterator();
            while (it.next()) |entry| {
                offset = try writeRecordAt(
                    self.io,
                    snapshot.file,
                    offset,
                    self.allocator,
                    .put,
                    store_family,
                    entry.key_ptr.*,
                    entry.value_ptr.*,
                    self.cfg.max_record_bytes,
                );
            }
        }
        try snapshot.file.sync(self.io);
        try snapshot.replace(self.io);
        try self.syncDir();

        const wal = self.wal_file.?;
        try wal.setLength(self.io, 0);
        try wal.sync(self.io);
        self.wal_offset = 0;
        try self.syncDir();
    }

    pub fn changeCount(self: *const OroStore) usize {
        return self.changefeed.count;
    }

    /// Returns recent mutations oldest-first. The returned slices are owned by
    /// the store and remain valid until the changefeed overwrites them.
    pub fn changeAt(self: *const OroStore, index: usize) ?Mutation {
        return self.changefeed.at(index);
    }

    fn ensureWal(self: *OroStore) !void {
        if (self.wal_file) |_| return;
        const file = try self.dir.createFile(self.io, self.wal_path, .{ .read = true, .truncate = false });
        self.wal_file = file;
        self.wal_offset = (try file.stat(self.io)).size;
    }

    const ReplayKind = enum {
        snapshot,
        wal,
    };

    fn replayFile(self: *OroStore, path: []const u8, replay_kind: ReplayKind) !void {
        var file = self.dir.openFile(self.io, path, .{ .mode = .read_only, .allow_directory = false }) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer file.close(self.io);

        const stat = try file.stat(self.io);
        if (stat.size == 0) return;
        if (replay_kind == .wal and stat.size > self.cfg.max_wal_bytes) return StoreError.RecordTooLarge;

        var offset: u64 = 0;
        var header: [record_header_len]u8 = undefined;
        while (offset < stat.size) {
            const record_offset = offset;
            const header_len = try file.readPositionalAll(self.io, &header, offset);
            if (header_len != header.len) {
                if (replay_kind == .wal) return;
                return StoreError.BadRecord;
            }
            offset += record_header_len;

            const payload_len = readU32(header[0..4]);
            const expected_sum = readU32(header[4..8]);
            const record_end = offset + payload_len;

            if (payload_len > self.cfg.max_record_bytes) return StoreError.RecordTooLarge;
            if (stat.size - offset < payload_len) {
                if (replay_kind == .wal) return;
                return StoreError.BadRecord;
            }

            const payload = try self.allocator.alloc(u8, payload_len);
            defer self.allocator.free(payload);
            const read_len = try file.readPositionalAll(self.io, payload, offset);
            if (read_len != payload.len) {
                if (replay_kind == .wal) return;
                return StoreError.BadRecord;
            }
            if (checksum(payload) != expected_sum) {
                if (replay_kind == .wal and record_end == stat.size) return;
                return StoreError.ChecksumMismatch;
            }
            self.applyPayload(payload) catch |err| switch (err) {
                StoreError.BadRecord,
                StoreError.UnknownFamily,
                StoreError.UnknownRecordKind,
                => if (replay_kind == .wal and record_end == stat.size) return else return err,
                else => return err,
            };
            if (replay_kind == .wal and isMutationPayload(payload)) self.next_seq += 1;
            offset = record_end;
            if (offset <= record_offset) return StoreError.BadRecord;
        }
    }

    fn appendRecord(
        self: *OroStore,
        kind: MutationKind,
        store_family: Family,
        key: []const u8,
        value: []const u8,
    ) !void {
        try self.ensureWal();
        const file = self.wal_file.?;
        const next_offset = try writeRecordAt(self.io, file, self.wal_offset, self.allocator, kind, store_family, key, value, self.cfg.max_record_bytes);
        try file.sync(self.io);
        self.wal_offset = next_offset;
    }

    fn applyPayload(self: *OroStore, payload: []const u8) !void {
        if (payload.len == 0) return StoreError.BadRecord;

        if (payload[0] == meta_kind_next_seq) {
            if (payload.len != meta_next_seq_payload_len) return StoreError.BadRecord;
            self.next_seq = readU64(payload[1..9]);
            return;
        }

        if (payload.len < payload_header_len) return StoreError.BadRecord;

        const kind: MutationKind = switch (payload[0]) {
            @intFromEnum(MutationKind.put) => .put,
            @intFromEnum(MutationKind.delete) => .delete,
            else => return StoreError.UnknownRecordKind,
        };
        const store_family = decodeFamily(payload[1]) orelse return StoreError.UnknownFamily;
        const key_len = readU32(payload[2..][0..4]);
        const value_len = readU32(payload[6..][0..4]);

        const needed = payload_header_len + @as(usize, key_len) +
            if (value_len == tombstone_len) 0 else @as(usize, value_len);
        if (payload.len != needed) return StoreError.BadRecord;

        const key = payload[payload_header_len..][0..key_len];
        if (kind == .delete) {
            if (value_len != tombstone_len) return StoreError.BadRecord;
            try self.applyDelete(store_family, key);
            return;
        }
        if (value_len == tombstone_len) return StoreError.BadRecord;
        const value = payload[payload_header_len + key_len ..][0..value_len];
        try self.applyPut(store_family, key, value);
    }

    fn applyPut(self: *OroStore, store_family: Family, key: []const u8, value: []const u8) !void {
        try self.maps[familyIndex(store_family)].put(key, value);
    }

    fn applyDelete(self: *OroStore, store_family: Family, key: []const u8) !void {
        self.maps[familyIndex(store_family)].delete(key);
    }

    fn recordMutation(
        self: *OroStore,
        store_family: Family,
        kind: MutationKind,
        key: []const u8,
        value: ?[]const u8,
    ) !void {
        try self.changefeed.push(.{
            .seq = self.next_seq,
            .family = store_family,
            .kind = kind,
            .key = key,
            .value = value,
        });
        self.next_seq += 1;
    }

    fn syncDir(self: *OroStore) !void {
        var dir_file = try self.dir.openFile(self.io, ".", .{ .mode = .read_only, .allow_directory = true });
        defer dir_file.close(self.io);
        try dir_file.sync(self.io);
    }
};

const family_count = @typeInfo(Family).@"enum".fields.len;
const families = std.enums.values(Family);

fn familyIndex(store_family: Family) usize {
    return @intFromEnum(store_family);
}

fn decodeFamily(value: u8) ?Family {
    return std.enums.fromInt(Family, value);
}

fn initMaps(allocator: std.mem.Allocator) [family_count]KvMap {
    var maps: [family_count]KvMap = undefined;
    for (&maps) |*map| map.* = KvMap.init(allocator);
    return maps;
}

const KvMap = struct {
    allocator: std.mem.Allocator,
    map: std.StringHashMap([]u8),

    fn init(allocator: std.mem.Allocator) KvMap {
        return .{
            .allocator = allocator,
            .map = std.StringHashMap([]u8).init(allocator),
        };
    }

    fn deinit(self: *KvMap) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.map.deinit();
    }

    fn put(self: *KvMap, key: []const u8, value: []const u8) !void {
        const gop = try self.map.getOrPut(key);
        if (gop.found_existing) {
            const next_value = try self.allocator.dupe(u8, value);
            self.allocator.free(gop.value_ptr.*);
            gop.value_ptr.* = next_value;
            return;
        }

        const owned_key = self.allocator.dupe(u8, key) catch |err| {
            _ = self.map.remove(key);
            return err;
        };
        gop.key_ptr.* = owned_key;
        errdefer {
            _ = self.map.remove(gop.key_ptr.*);
            self.allocator.free(gop.key_ptr.*);
        }
        gop.value_ptr.* = try self.allocator.dupe(u8, value);
    }

    fn get(self: *const KvMap, key: []const u8) ?[]const u8 {
        return self.map.get(key);
    }

    fn delete(self: *KvMap, key: []const u8) void {
        if (self.map.getEntry(key)) |entry| {
            const owned_key = entry.key_ptr.*;
            const owned_value = entry.value_ptr.*;
            self.map.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_key);
            self.allocator.free(owned_value);
        }
    }
};

const ChangeFeed = struct {
    allocator: std.mem.Allocator,
    entries: []?OwnedMutation,
    start: usize = 0,
    count: usize = 0,

    fn init(allocator: std.mem.Allocator, capacity: usize) !ChangeFeed {
        const entries = try allocator.alloc(?OwnedMutation, capacity);
        @memset(entries, null);
        return .{ .allocator = allocator, .entries = entries };
    }

    fn deinit(self: *ChangeFeed) void {
        for (self.entries) |*entry| {
            if (entry.*) |*mutation| mutation.deinit(self.allocator);
        }
        self.allocator.free(self.entries);
    }

    fn push(self: *ChangeFeed, mutation: Mutation) !void {
        if (self.entries.len == 0) return;

        const owned = try OwnedMutation.from(self.allocator, mutation);

        if (self.count < self.entries.len) {
            const index = (self.start + self.count) % self.entries.len;
            self.entries[index] = owned;
            self.count += 1;
        } else {
            const index = self.start;
            if (self.entries[index]) |*old| old.deinit(self.allocator);
            self.entries[index] = null;
            self.entries[index] = owned;
            self.start = (self.start + 1) % self.entries.len;
        }
    }

    fn at(self: *const ChangeFeed, index: usize) ?Mutation {
        if (index >= self.count) return null;
        const real_index = (self.start + index) % self.entries.len;
        return self.entries[real_index].?.view();
    }
};

const OwnedMutation = struct {
    seq: u64,
    family: Family,
    kind: MutationKind,
    key: []u8,
    value: ?[]u8,

    fn from(allocator: std.mem.Allocator, mutation: Mutation) !OwnedMutation {
        const owned_key = try allocator.dupe(u8, mutation.key);
        errdefer allocator.free(owned_key);
        const owned_value = if (mutation.value) |value| try allocator.dupe(u8, value) else null;
        return .{
            .seq = mutation.seq,
            .family = mutation.family,
            .kind = mutation.kind,
            .key = owned_key,
            .value = owned_value,
        };
    }

    fn deinit(self: *OwnedMutation, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        if (self.value) |value| allocator.free(value);
    }

    fn view(self: *const OwnedMutation) Mutation {
        return .{
            .seq = self.seq,
            .family = self.family,
            .kind = self.kind,
            .key = self.key,
            .value = self.value,
        };
    }
};

fn writeRecordAt(
    io: std.Io,
    file: std.Io.File,
    offset: u64,
    allocator: std.mem.Allocator,
    kind: MutationKind,
    store_family: Family,
    key: []const u8,
    value: []const u8,
    max_record_bytes: usize,
) !u64 {
    if (key.len > std.math.maxInt(u32) or value.len > std.math.maxInt(u32))
        return StoreError.RecordTooLarge;

    const payload_len = payload_header_len + key.len + if (kind == .delete) 0 else value.len;
    if (payload_len > max_record_bytes) return StoreError.RecordTooLarge;

    const record = try allocator.alloc(u8, record_header_len + payload_len);
    defer allocator.free(record);

    writeU32(record[0..4], @intCast(payload_len));
    const payload = record[record_header_len..];
    payload[0] = @intFromEnum(kind);
    payload[1] = @intFromEnum(store_family);
    writeU32(payload[2..][0..4], @intCast(key.len));
    writeU32(payload[6..][0..4], if (kind == .delete) tombstone_len else @as(u32, @intCast(value.len)));
    @memcpy(payload[payload_header_len..][0..key.len], key);
    if (kind == .put)
        @memcpy(payload[payload_header_len + key.len ..][0..value.len], value);
    writeU32(record[4..][0..4], checksum(payload));

    try file.writePositionalAll(io, record, offset);
    return offset + record.len;
}

fn writeNextSeqRecordAt(
    io: std.Io,
    file: std.Io.File,
    offset: u64,
    allocator: std.mem.Allocator,
    next_seq: u64,
) !u64 {
    const record = try allocator.alloc(u8, record_header_len + meta_next_seq_payload_len);
    defer allocator.free(record);

    writeU32(record[0..4], meta_next_seq_payload_len);
    const payload = record[record_header_len..];
    payload[0] = meta_kind_next_seq;
    writeU64(payload[1..9], next_seq);
    writeU32(record[4..][0..4], checksum(payload));

    try file.writePositionalAll(io, record, offset);
    return offset + record.len;
}

fn isMutationPayload(payload: []const u8) bool {
    if (payload.len == 0) return false;
    return payload[0] == @intFromEnum(MutationKind.put) or
        payload[0] == @intFromEnum(MutationKind.delete);
}

fn checksum(payload: []const u8) u32 {
    return std.hash.Fnv1a_32.hash(payload);
}

fn readU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .little);
}

fn readU64(bytes: *const [8]u8) u64 {
    return std.mem.readInt(u64, bytes, .little);
}

fn writeU32(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .little);
}

fn writeU64(bytes: *[8]u8, value: u64) void {
    std.mem.writeInt(u64, bytes, value, .little);
}

fn openTestStore(tmp: std.testing.TmpDir, name: []const u8) !OroStore {
    return OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, name);
}

test "put/get round-trip per family" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "roundtrip.wal");
    defer store.deinit();

    try store.family(.accounts).put("alice", "account:alice");
    try store.family(.nicks).put("Alice", "alice");
    try store.family(.chanregs).put("#zig", "founder=alice");
    try store.family(.bans).put("kline:test", "bad.host");
    try store.family(.memos).put("memo:1", "hello");
    try store.family(.vhosts).put("alice", "staff.example");
    try store.family(.props).put("#zig:title", "Zig");
    try store.family(.history).put("#zig:1", "message");

    try std.testing.expectEqualStrings("account:alice", store.family(.accounts).get("alice").?);
    try std.testing.expectEqualStrings("alice", store.family(.nicks).get("Alice").?);
    try std.testing.expectEqualStrings("founder=alice", store.family(.chanregs).get("#zig").?);
    try std.testing.expectEqualStrings("bad.host", store.family(.bans).get("kline:test").?);
    try std.testing.expectEqualStrings("hello", store.family(.memos).get("memo:1").?);
    try std.testing.expectEqualStrings("staff.example", store.family(.vhosts).get("alice").?);
    try std.testing.expectEqualStrings("Zig", store.family(.props).get("#zig:title").?);
    try std.testing.expectEqualStrings("message", store.family(.history).get("#zig:1").?);
}

test "WAL replay reconstructs state after reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "replay.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "v1");
        try store.family(.accounts).put("alice", "v2");
        try store.family(.history).put("#z:1", "hi");
    }
    {
        var store = try openTestStore(tmp, "replay.wal");
        defer store.deinit();
        try std.testing.expectEqualStrings("v2", store.family(.accounts).get("alice").?);
        try std.testing.expectEqualStrings("hi", store.family(.history).get("#z:1").?);
    }
}

test "checksum mismatch is detected and rejected" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "bad.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "ok");
        try store.family(.accounts).put("bob", "still-ok");
    }

    var file = try tmp.dir.openFile(std.testing.io, "bad.wal", .{ .mode = .read_write, .allow_directory = false });
    defer file.close(std.testing.io);
    try file.writePositionalAll(std.testing.io, &.{0xAA}, 6);

    try std.testing.expectError(StoreError.ChecksumMismatch, openTestStore(tmp, "bad.wal"));
}

test "torn final WAL record is ignored after replaying valid prefix" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "torn.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "ok");
    }

    var file = try tmp.dir.openFile(std.testing.io, "torn.wal", .{ .mode = .read_write, .allow_directory = false });
    defer file.close(std.testing.io);
    const stat = try file.stat(std.testing.io);
    try file.writePositionalAll(std.testing.io, &.{ 1, 0, 0, 0 }, stat.size);
    try file.sync(std.testing.io);

    var store = try openTestStore(tmp, "torn.wal");
    defer store.deinit();
    try std.testing.expectEqualStrings("ok", store.family(.accounts).get("alice").?);
}

test "checksum-bad final WAL record is ignored after replaying valid prefix" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "final-checksum.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "ok");
    }

    var file = try tmp.dir.openFile(std.testing.io, "final-checksum.wal", .{ .mode = .read_write, .allow_directory = false });
    defer file.close(std.testing.io);
    const stat = try file.stat(std.testing.io);
    _ = try writeRecordAt(std.testing.io, file, stat.size, std.testing.allocator, .put, .accounts, "bob", "bad", default_max_record_len);
    try file.writePositionalAll(std.testing.io, &.{0xAA}, stat.size + 6);
    try file.sync(std.testing.io);

    var store = try openTestStore(tmp, "final-checksum.wal");
    defer store.deinit();
    try std.testing.expectEqualStrings("ok", store.family(.accounts).get("alice").?);
    try std.testing.expect(store.family(.accounts).get("bob") == null);
}

test "snapshot+truncate preserves data" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "snapshot.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "v1");
        try store.family(.nicks).put("Alice", "alice");
        try store.snapshotAndTruncate();
        try store.family(.accounts).put("bob", "v2");
    }
    {
        var store = try openTestStore(tmp, "snapshot.wal");
        defer store.deinit();
        try std.testing.expectEqualStrings("v1", store.family(.accounts).get("alice").?);
        try std.testing.expectEqualStrings("alice", store.family(.nicks).get("Alice").?);
        try std.testing.expectEqualStrings("v2", store.family(.accounts).get("bob").?);
    }
}

test "changefeed sequence persists across snapshot reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "seq.wal");
        defer store.deinit();
        try store.family(.accounts).put("alice", "v1");
        try store.snapshotAndTruncate();
    }
    {
        var store = try openTestStore(tmp, "seq.wal");
        defer store.deinit();
        try store.family(.accounts).put("bob", "v2");
        const mutation = store.changeAt(0).?;
        try std.testing.expectEqual(@as(u64, 2), mutation.seq);
        try std.testing.expectEqualStrings("bob", mutation.key);
    }
}

test "changefeed records mutations" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "changes.wal");
    defer store.deinit();

    try store.family(.accounts).put("alice", "v1");
    try store.family(.accounts).put("bob", "v2");
    try store.family(.accounts).delete("alice");

    try std.testing.expectEqual(@as(usize, 3), store.changeCount());
    const first = store.changeAt(0).?;
    try std.testing.expectEqual(@as(u64, 1), first.seq);
    try std.testing.expectEqual(Family.accounts, first.family);
    try std.testing.expectEqual(MutationKind.put, first.kind);
    try std.testing.expectEqualStrings("alice", first.key);
    try std.testing.expectEqualStrings("v1", first.value.?);

    const last = store.changeAt(2).?;
    try std.testing.expectEqual(@as(u64, 3), last.seq);
    try std.testing.expectEqual(MutationKind.delete, last.kind);
    try std.testing.expectEqualStrings("alice", last.key);
    try std.testing.expect(last.value == null);
    try std.testing.expect(store.family(.accounts).get("alice") == null);
}

test "storage Config defaults preserve historical limits" {
    const cfg = Config{};
    try std.testing.expectEqual(@as(usize, default_max_record_len), cfg.max_record_bytes);
    try std.testing.expectEqual(@as(usize, default_max_wal_len), cfg.max_wal_bytes);
    try std.testing.expectEqual(@as(usize, default_changefeed_capacity), cfg.changefeed_capacity);
}

test "storage Config.applyToml overlays [storage] keys" {
    var doc = try toml.parse(
        std.testing.allocator,
        "[storage]\nmax_record_bytes = 65536\nmax_wal_bytes = 1048576\nchangefeed_capacity = 128\n",
    );
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(usize, 65536), cfg.max_record_bytes);
    try std.testing.expectEqual(@as(usize, 1048576), cfg.max_wal_bytes);
    try std.testing.expectEqual(@as(usize, 128), cfg.changefeed_capacity);
}

test "storage Config.applyToml leaves defaults when section absent" {
    var doc = try toml.parse(std.testing.allocator, "[other]\nx = 1\n");
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(usize, default_max_record_len), cfg.max_record_bytes);
    try std.testing.expectEqual(@as(usize, default_max_wal_len), cfg.max_wal_bytes);
    try std.testing.expectEqual(@as(usize, default_changefeed_capacity), cfg.changefeed_capacity);
}

test "openWithConfig honours a smaller record limit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        "cfg-limit.wal",
        .{ .max_record_bytes = 16 },
    );
    defer store.deinit();

    try std.testing.expectError(
        StoreError.RecordTooLarge,
        store.family(.accounts).put("alice", "this value is definitely longer than sixteen bytes"),
    );
}
