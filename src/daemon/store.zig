//! MizuStore embedded persistence skeleton.
//!
//! This is intentionally small, Zig-native, and standalone: an in-memory typed
//! key/value store backed by a checksummed append-only log, with snapshot
//! compaction and a bounded recent-mutation feed for service sync.
const std = @import("std");

const record_header_len = 8;
const payload_header_len = 10;
const max_record_len = 16 * 1024 * 1024;
const tombstone_len = std.math.maxInt(u32);

pub const StoreError = error{
    BadRecord,
    ChecksumMismatch,
    UnknownFamily,
    UnknownRecordKind,
    RecordTooLarge,
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
        store: *MizuStore,

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

pub const MizuStore = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    wal_path: []u8,
    snapshot_path: []u8,
    maps: [family_count]KvMap,
    changefeed: ChangeFeed,
    next_seq: u64 = 1,

    /// Opens `wal_path` under `dir`, replays `<wal_path>.snap` first, then WAL.
    pub fn open(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        wal_path: []const u8,
    ) !MizuStore {
        const owned_wal = try allocator.dupe(u8, wal_path);
        const owned_snapshot = std.mem.concat(allocator, u8, &.{ wal_path, ".snap" }) catch |err| {
            allocator.free(owned_wal);
            return err;
        };

        var store = MizuStore{
            .allocator = allocator,
            .io = io,
            .dir = dir,
            .wal_path = owned_wal,
            .snapshot_path = owned_snapshot,
            .maps = initMaps(allocator),
            .changefeed = try ChangeFeed.init(allocator, 64),
        };
        errdefer store.deinit();

        try store.replayFile(store.snapshot_path);
        try store.replayFile(store.wal_path);
        try store.ensureWal();
        return store;
    }

    pub fn deinit(self: *MizuStore) void {
        for (&self.maps) |*map| map.deinit();
        self.changefeed.deinit();
        self.allocator.free(self.wal_path);
        self.allocator.free(self.snapshot_path);
        self.* = undefined;
    }

    /// Returns the comptime-typed API for one column family.
    pub fn family(self: *MizuStore, comptime store_family: Family) ColumnFamily(store_family) {
        return .{ .store = self };
    }

    pub fn put(self: *MizuStore, store_family: Family, key: []const u8, value: []const u8) !void {
        try self.appendRecord(.put, store_family, key, value);
        try self.applyPut(store_family, key, value);
        try self.recordMutation(store_family, .put, key, value);
    }

    pub fn get(self: *const MizuStore, store_family: Family, key: []const u8) ?[]const u8 {
        return self.maps[familyIndex(store_family)].get(key);
    }

    pub fn delete(self: *MizuStore, store_family: Family, key: []const u8) !void {
        try self.appendRecord(.delete, store_family, key, "");
        try self.applyDelete(store_family, key);
        try self.recordMutation(store_family, .delete, key, null);
    }

    /// Writes current state to a snapshot and truncates the WAL.
    pub fn snapshotAndTruncate(self: *MizuStore) !void {
        const tmp_path = try std.mem.concat(self.allocator, u8, &.{ self.snapshot_path, ".tmp" });
        defer self.allocator.free(tmp_path);

        var snapshot = try self.dir.createFile(self.io, tmp_path, .{ .read = true, .truncate = true });
        defer snapshot.close(self.io);

        var offset: u64 = 0;
        for (families) |store_family| {
            var it = self.maps[familyIndex(store_family)].map.iterator();
            while (it.next()) |entry| {
                offset = try writeRecordAt(
                    self.io,
                    snapshot,
                    offset,
                    self.allocator,
                    .put,
                    store_family,
                    entry.key_ptr.*,
                    entry.value_ptr.*,
                );
            }
        }
        try snapshot.sync(self.io);
        self.dir.deleteFile(self.io, self.snapshot_path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        try self.dir.rename(tmp_path, self.dir, self.snapshot_path, self.io);

        var wal = try self.dir.createFile(self.io, self.wal_path, .{ .read = true, .truncate = true });
        defer wal.close(self.io);
        try wal.sync(self.io);
    }

    pub fn changeCount(self: *const MizuStore) usize {
        return self.changefeed.count;
    }

    /// Returns recent mutations oldest-first. The returned slices are owned by
    /// the store and remain valid until the changefeed overwrites them.
    pub fn changeAt(self: *const MizuStore, index: usize) ?Mutation {
        return self.changefeed.at(index);
    }

    fn ensureWal(self: *MizuStore) !void {
        var file = try self.dir.createFile(self.io, self.wal_path, .{ .read = true, .truncate = false });
        file.close(self.io);
    }

    fn replayFile(self: *MizuStore, path: []const u8) !void {
        var file = self.dir.openFile(self.io, path, .{ .mode = .read_only, .allow_directory = false }) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer file.close(self.io);

        const stat = try file.stat(self.io);
        if (stat.size == 0) return;
        if (stat.size > max_record_len * 1024) return StoreError.RecordTooLarge;

        const bytes = try self.allocator.alloc(u8, @intCast(stat.size));
        defer self.allocator.free(bytes);
        const read_len = try file.readPositionalAll(self.io, bytes, 0);
        if (read_len != bytes.len) return StoreError.BadRecord;

        var cursor: usize = 0;
        while (cursor < bytes.len) {
            if (bytes.len - cursor < record_header_len) return StoreError.BadRecord;
            const payload_len = readU32(bytes[cursor..][0..4]);
            const expected_sum = readU32(bytes[cursor + 4 ..][0..4]);
            cursor += record_header_len;

            if (payload_len > max_record_len) return StoreError.RecordTooLarge;
            if (bytes.len - cursor < payload_len) return StoreError.BadRecord;

            const payload = bytes[cursor..][0..payload_len];
            if (checksum(payload) != expected_sum) return StoreError.ChecksumMismatch;
            try self.applyPayload(payload);
            cursor += payload_len;
        }
    }

    fn appendRecord(
        self: *MizuStore,
        kind: MutationKind,
        store_family: Family,
        key: []const u8,
        value: []const u8,
    ) !void {
        var file = try self.dir.createFile(self.io, self.wal_path, .{ .read = true, .truncate = false });
        defer file.close(self.io);
        const offset = (try file.stat(self.io)).size;
        _ = try writeRecordAt(self.io, file, offset, self.allocator, kind, store_family, key, value);
        try file.sync(self.io);
    }

    fn applyPayload(self: *MizuStore, payload: []const u8) !void {
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

    fn applyPut(self: *MizuStore, store_family: Family, key: []const u8, value: []const u8) !void {
        try self.maps[familyIndex(store_family)].put(key, value);
    }

    fn applyDelete(self: *MizuStore, store_family: Family, key: []const u8) !void {
        self.maps[familyIndex(store_family)].delete(key);
    }

    fn recordMutation(
        self: *MizuStore,
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
};

const family_count = @typeInfo(Family).@"enum".fields.len;
const families = [_]Family{ .accounts, .nicks, .chanregs, .bans, .memos, .vhosts, .props, .history };

fn familyIndex(store_family: Family) usize {
    return @intFromEnum(store_family);
}

fn decodeFamily(value: u8) ?Family {
    return switch (value) {
        @intFromEnum(Family.accounts) => .accounts,
        @intFromEnum(Family.nicks) => .nicks,
        @intFromEnum(Family.chanregs) => .chanregs,
        @intFromEnum(Family.bans) => .bans,
        @intFromEnum(Family.memos) => .memos,
        @intFromEnum(Family.vhosts) => .vhosts,
        @intFromEnum(Family.props) => .props,
        @intFromEnum(Family.history) => .history,
        else => null,
    };
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

        errdefer _ = self.map.remove(key);
        gop.key_ptr.* = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(gop.key_ptr.*);
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

        const index = if (self.count < self.entries.len) blk: {
            const write_index = (self.start + self.count) % self.entries.len;
            self.count += 1;
            break :blk write_index;
        } else blk: {
            const write_index = self.start;
            if (self.entries[write_index]) |*old| old.deinit(self.allocator);
            self.start = (self.start + 1) % self.entries.len;
            break :blk write_index;
        };

        self.entries[index] = try OwnedMutation.from(self.allocator, mutation);
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
) !u64 {
    if (key.len > std.math.maxInt(u32) or value.len > std.math.maxInt(u32))
        return StoreError.RecordTooLarge;

    const payload_len = payload_header_len + key.len + if (kind == .delete) 0 else value.len;
    if (payload_len > max_record_len) return StoreError.RecordTooLarge;

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

fn checksum(payload: []const u8) u32 {
    return std.hash.Fnv1a_32.hash(payload);
}

fn readU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .little);
}

fn writeU32(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .little);
}

fn openTestStore(tmp: std.testing.TmpDir, name: []const u8) !MizuStore {
    return MizuStore.open(std.testing.allocator, std.testing.io, tmp.dir, name);
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
    }

    var file = try tmp.dir.openFile(std.testing.io, "bad.wal", .{ .mode = .read_write, .allow_directory = false });
    defer file.close(std.testing.io);
    try file.writePositionalAll(std.testing.io, &.{0xAA}, 6);

    try std.testing.expectError(StoreError.ChecksumMismatch, openTestStore(tmp, "bad.wal"));
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
