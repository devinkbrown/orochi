//! Bounded file metadata registry for daemon-side media references.
const std = @import("std");

pub const max_entries: usize = 8192;
pub const max_id_len: usize = 128;
pub const max_name_len: usize = 255;
pub const max_owner_len: usize = 128;

pub const Error = std.mem.Allocator.Error || error{
    InvalidId,
    FieldTooLong,
    TooManyEntries,
};

pub const Meta = struct {
    name: []const u8,
    size: u64,
    owner: []const u8,
    at_ms: i64,
};

const StoredMeta = struct {
    name: []u8,
    size: u64,
    owner: []u8,
    at_ms: i64,
};

pub const FileMeta = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap(StoredMeta),
    limit: usize,

    pub fn init(allocator: std.mem.Allocator) FileMeta {
        return initWithLimit(allocator, max_entries);
    }

    pub fn initWithLimit(allocator: std.mem.Allocator, limit: usize) FileMeta {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap(StoredMeta).init(allocator),
            .limit = limit,
        };
    }

    pub fn deinit(self: *FileMeta) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            freeStored(self.allocator, entry.value_ptr.*);
        }
        self.entries.deinit();
        self.* = undefined;
    }

    pub fn put(self: *FileMeta, id: []const u8, name: []const u8, size: u64, owner: []const u8, now: i64) Error!void {
        try validate(id, name, owner);

        if (self.entries.getEntry(id)) |entry| {
            const next_name = try self.allocator.dupe(u8, name);
            errdefer self.allocator.free(next_name);
            const next_owner = try self.allocator.dupe(u8, owner);
            errdefer self.allocator.free(next_owner);

            freeStored(self.allocator, entry.value_ptr.*);
            entry.value_ptr.* = .{ .name = next_name, .size = size, .owner = next_owner, .at_ms = now };
            return;
        }

        if (self.entries.count() >= self.limit) return error.TooManyEntries;

        const owned_id = try self.allocator.dupe(u8, id);
        errdefer self.allocator.free(owned_id);
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_owner = try self.allocator.dupe(u8, owner);
        errdefer self.allocator.free(owned_owner);

        try self.entries.putNoClobber(owned_id, .{
            .name = owned_name,
            .size = size,
            .owner = owned_owner,
            .at_ms = now,
        });
    }

    pub fn get(self: *const FileMeta, id: []const u8) ?Meta {
        const stored = self.entries.get(id) orelse return null;
        return .{
            .name = stored.name,
            .size = stored.size,
            .owner = stored.owner,
            .at_ms = stored.at_ms,
        };
    }

    pub fn remove(self: *FileMeta, id: []const u8) bool {
        const kv = self.entries.fetchRemove(id) orelse return false;
        self.allocator.free(kv.key);
        freeStored(self.allocator, kv.value);
        return true;
    }

    pub fn count(self: *const FileMeta) usize {
        return self.entries.count();
    }

    fn validate(id: []const u8, name: []const u8, owner: []const u8) Error!void {
        if (id.len == 0) return error.InvalidId;
        if (id.len > max_id_len or name.len > max_name_len or owner.len > max_owner_len) return error.FieldTooLong;
    }

    fn freeStored(allocator: std.mem.Allocator, meta: StoredMeta) void {
        allocator.free(meta.name);
        allocator.free(meta.owner);
    }
};

const testing = std.testing;

test "put and get returns borrowed metadata" {
    var registry = FileMeta.init(testing.allocator);
    defer registry.deinit();

    try registry.put("f1", "clip.webm", 42, "alice", 1234);
    const meta = registry.get("f1").?;
    try testing.expectEqualStrings("clip.webm", meta.name);
    try testing.expectEqual(@as(u64, 42), meta.size);
    try testing.expectEqualStrings("alice", meta.owner);
    try testing.expectEqual(@as(i64, 1234), meta.at_ms);
}

test "put replaces existing entry without growing the table" {
    var registry = FileMeta.init(testing.allocator);
    defer registry.deinit();

    try registry.put("f1", "old.bin", 1, "alice", 10);
    try registry.put("f1", "new.bin", 99, "bob", 20);
    try testing.expectEqual(@as(usize, 1), registry.count());

    const meta = registry.get("f1").?;
    try testing.expectEqualStrings("new.bin", meta.name);
    try testing.expectEqual(@as(u64, 99), meta.size);
    try testing.expectEqualStrings("bob", meta.owner);
    try testing.expectEqual(@as(i64, 20), meta.at_ms);
}

test "remove reports presence and frees the slot" {
    var registry = FileMeta.init(testing.allocator);
    defer registry.deinit();

    try registry.put("f1", "one.dat", 1, "alice", 1);
    try testing.expect(registry.remove("f1"));
    try testing.expect(!registry.remove("f1"));
    try testing.expect(registry.get("f1") == null);
    try testing.expectEqual(@as(usize, 0), registry.count());
}

test "entry limit is enforced" {
    var registry = FileMeta.initWithLimit(testing.allocator, 1);
    defer registry.deinit();

    try registry.put("f1", "one.dat", 1, "alice", 1);
    try testing.expectError(error.TooManyEntries, registry.put("f2", "two.dat", 2, "bob", 2));
}
