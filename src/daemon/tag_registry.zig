//! Tag-to-entity registry with owned strings and deterministic cleanup.
const std = @import("std");

pub const TagRegistry = struct {
    allocator: std.mem.Allocator,
    buckets: std.StringHashMap(EntityList),

    pub fn init(allocator: std.mem.Allocator) TagRegistry {
        return .{
            .allocator = allocator,
            .buckets = std.StringHashMap(EntityList).init(allocator),
        };
    }

    pub fn deinit(self: *TagRegistry) void {
        var it = self.buckets.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.buckets.deinit();
        self.* = undefined;
    }

    pub fn tag(self: *TagRegistry, name: []const u8, entity: []const u8) !void {
        var list = try self.ensureTag(name);
        if (list.indexOf(entity) != null) return;
        const owned_entity = try self.allocator.dupe(u8, entity);
        errdefer self.allocator.free(owned_entity);
        try list.ids.append(self.allocator, owned_entity);
    }

    pub fn untag(self: *TagRegistry, name: []const u8, entity: []const u8) bool {
        const entry = self.buckets.getEntry(name) orelse return false;
        const index = entry.value_ptr.indexOf(entity) orelse return false;
        const owned_entity = entry.value_ptr.ids.orderedRemove(index);
        self.allocator.free(owned_entity);

        if (entry.value_ptr.ids.items.len == 0) {
            const owned_name = entry.key_ptr.*;
            entry.value_ptr.deinit(self.allocator);
            self.buckets.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_name);
        }
        return true;
    }

    pub fn entities(self: *const TagRegistry, name: []const u8) []const []const u8 {
        const list = self.buckets.getPtr(name) orelse return &.{};
        return list.ids.items;
    }

    fn ensureTag(self: *TagRegistry, name: []const u8) !*EntityList {
        if (self.buckets.getPtr(name)) |list| return list;
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        try self.buckets.putNoClobber(owned_name, .{});
        return self.buckets.getPtr(name).?;
    }
};

const EntityList = struct {
    ids: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *EntityList, allocator: std.mem.Allocator) void {
        for (self.ids.items) |id| allocator.free(id);
        self.ids.deinit(allocator);
        self.* = undefined;
    }

    fn indexOf(self: *const EntityList, entity: []const u8) ?usize {
        for (self.ids.items, 0..) |id, index| {
            if (std.mem.eql(u8, id, entity)) return index;
        }
        return null;
    }
};

const testing = std.testing;

test "tag records entities and deduplicates within a tag" {
    var registry = TagRegistry.init(testing.allocator);
    defer registry.deinit();

    try registry.tag("ops", "u1");
    try registry.tag("ops", "u1");
    try registry.tag("ops", "u2");

    const ids = registry.entities("ops");
    try testing.expectEqual(@as(usize, 2), ids.len);
    try testing.expectEqualStrings("u1", ids[0]);
    try testing.expectEqualStrings("u2", ids[1]);
}

test "untag reports presence and prunes empty tag buckets" {
    var registry = TagRegistry.init(testing.allocator);
    defer registry.deinit();

    try registry.tag("staff", "alpha");
    try testing.expect(registry.untag("staff", "alpha"));
    try testing.expect(!registry.untag("staff", "alpha"));
    try testing.expectEqual(@as(usize, 0), registry.entities("staff").len);
}

test "different tags keep independent entity sets" {
    var registry = TagRegistry.init(testing.allocator);
    defer registry.deinit();

    try registry.tag("blue", "n1");
    try registry.tag("green", "n1");
    try registry.tag("green", "n2");

    try testing.expectEqual(@as(usize, 1), registry.entities("blue").len);
    try testing.expectEqual(@as(usize, 2), registry.entities("green").len);
    try testing.expect(registry.untag("green", "n1"));
    try testing.expectEqualStrings("n2", registry.entities("green")[0]);
    try testing.expectEqualStrings("n1", registry.entities("blue")[0]);
}
