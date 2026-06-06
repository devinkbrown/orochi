//! Bounded alias-to-target resolver with owned strings.
const std = @import("std");

pub const AliasResolver = struct {
    allocator: std.mem.Allocator,
    max_depth: usize,
    links: std.StringHashMap([]const u8),

    pub fn init(allocator: std.mem.Allocator) AliasResolver {
        return initWithMaxDepth(allocator, 32);
    }

    pub fn initWithMaxDepth(allocator: std.mem.Allocator, max_depth: usize) AliasResolver {
        return .{
            .allocator = allocator,
            .max_depth = @max(max_depth, 1),
            .links = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *AliasResolver) void {
        var it = self.links.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.links.deinit();
        self.* = undefined;
    }

    pub fn set(self: *AliasResolver, alias: []const u8, target: []const u8) !void {
        if (self.links.getEntry(alias)) |entry| {
            const owned_target = try self.allocator.dupe(u8, target);
            self.allocator.free(entry.value_ptr.*);
            entry.value_ptr.* = owned_target;
            return;
        }

        const owned_alias = try self.allocator.dupe(u8, alias);
        errdefer self.allocator.free(owned_alias);
        const owned_target = try self.allocator.dupe(u8, target);
        errdefer self.allocator.free(owned_target);
        try self.links.putNoClobber(owned_alias, owned_target);
    }

    pub fn resolve(self: *const AliasResolver, alias: []const u8) ?[]const u8 {
        var current = alias;
        var depth: usize = 0;

        while (depth < self.max_depth) : (depth += 1) {
            const target = self.links.get(current) orelse return if (depth == 0) null else current;
            if (std.mem.eql(u8, target, current)) return null;
            current = target;
        }

        return null;
    }

    pub fn remove(self: *AliasResolver, alias: []const u8) bool {
        const removed = self.links.fetchRemove(alias) orelse return false;
        self.allocator.free(removed.key);
        self.allocator.free(removed.value);
        return true;
    }
};

const testing = std.testing;

test "resolve follows aliases to the final target" {
    var resolver = AliasResolver.init(testing.allocator);
    defer resolver.deinit();

    try resolver.set("nick", "account");
    try resolver.set("account", "person-42");

    try testing.expectEqualStrings("person-42", resolver.resolve("nick").?);
    try testing.expectEqualStrings("person-42", resolver.resolve("account").?);
    try testing.expectEqual(@as(?[]const u8, null), resolver.resolve("missing"));
}

test "set replaces target without duplicating alias entries" {
    var resolver = AliasResolver.init(testing.allocator);
    defer resolver.deinit();

    try resolver.set("service", "old");
    try resolver.set("service", "new");

    try testing.expectEqualStrings("new", resolver.resolve("service").?);
    try testing.expectEqual(@as(usize, 1), resolver.links.count());
}

test "remove reports whether an alias existed" {
    var resolver = AliasResolver.init(testing.allocator);
    defer resolver.deinit();

    try resolver.set("short", "long");
    try testing.expect(resolver.remove("short"));
    try testing.expect(!resolver.remove("short"));
    try testing.expectEqual(@as(?[]const u8, null), resolver.resolve("short"));
}

test "cycles and excessive depth resolve to null" {
    var resolver = AliasResolver.initWithMaxDepth(testing.allocator, 3);
    defer resolver.deinit();

    try resolver.set("a", "b");
    try resolver.set("b", "a");
    try resolver.set("x", "y");
    try resolver.set("y", "z");
    try resolver.set("z", "done");

    try testing.expectEqual(@as(?[]const u8, null), resolver.resolve("a"));
    try testing.expectEqual(@as(?[]const u8, null), resolver.resolve("x"));
}
