const std = @import("std");

pub const FeatureFlag = struct {
    allocator: std.mem.Allocator,
    flags: std.StringHashMap(bool),
    names: std.ArrayList([]const u8),

    pub fn init(allocator: std.mem.Allocator) FeatureFlag {
        return .{
            .allocator = allocator,
            .flags = std.StringHashMap(bool).init(allocator),
            .names = .empty,
        };
    }

    pub fn deinit(self: *FeatureFlag) void {
        for (self.names.items) |name| {
            self.allocator.free(name);
        }
        self.names.deinit(self.allocator);
        self.flags.deinit();
    }

    pub fn set(self: *FeatureFlag, name: []const u8, on: bool) !void {
        if (self.flags.getPtr(name)) |value| {
            value.* = on;
            return;
        }

        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);

        try self.names.append(self.allocator, owned_name);
        errdefer _ = self.names.pop();

        try self.flags.put(owned_name, on);
    }

    pub fn enabled(self: *FeatureFlag, name: []const u8) bool {
        return self.flags.get(name) orelse false;
    }

    pub fn list(self: *FeatureFlag) []const []const u8 {
        return self.names.items;
    }
};

test "FeatureFlag defaults to disabled" {
    var flags = FeatureFlag.init(std.testing.allocator);
    defer flags.deinit();

    try std.testing.expect(!flags.enabled("new-search"));
    try std.testing.expectEqual(@as(usize, 0), flags.list().len);
}

test "FeatureFlag sets and updates a flag" {
    var flags = FeatureFlag.init(std.testing.allocator);
    defer flags.deinit();

    try flags.set("registration", true);
    try std.testing.expect(flags.enabled("registration"));
    try flags.set("registration", false);
    try std.testing.expect(!flags.enabled("registration"));
    try std.testing.expectEqual(@as(usize, 1), flags.list().len);
}

test "FeatureFlag lists names in insertion order" {
    var flags = FeatureFlag.init(std.testing.allocator);
    defer flags.deinit();

    try flags.set("alpha", true);
    try flags.set("beta", false);
    try flags.set("gamma", true);

    const names = flags.list();
    try std.testing.expectEqualStrings("alpha", names[0]);
    try std.testing.expectEqualStrings("beta", names[1]);
    try std.testing.expectEqualStrings("gamma", names[2]);
}
