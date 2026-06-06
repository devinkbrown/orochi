const std = @import("std");

pub const Error = std.mem.Allocator.Error;

pub const Delegation = struct {
    allocator: std.mem.Allocator,
    edges: std.StringHashMap([]u8),

    pub fn init(allocator: std.mem.Allocator) Delegation {
        return .{
            .allocator = allocator,
            .edges = std.StringHashMap([]u8).init(allocator),
        };
    }

    pub fn deinit(self: *Delegation) void {
        var it = self.edges.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.edges.deinit();
        self.* = undefined;
    }

    pub fn setDelegate(self: *Delegation, a: []const u8, b: []const u8) Error!bool {
        if (self.wouldCycle(a, b)) return false;

        if (self.edges.getEntry(a)) |entry| {
            const owned_delegate = try self.allocator.dupe(u8, b);
            self.allocator.free(entry.value_ptr.*);
            entry.value_ptr.* = owned_delegate;
            return true;
        }

        const owned_account = try self.allocator.dupe(u8, a);
        errdefer self.allocator.free(owned_account);
        const owned_delegate = try self.allocator.dupe(u8, b);
        errdefer self.allocator.free(owned_delegate);
        try self.edges.putNoClobber(owned_account, owned_delegate);
        return true;
    }

    pub fn resolve(self: *const Delegation, a: []const u8) []const u8 {
        var cursor = a;
        var steps: usize = 0;
        const limit = self.edges.count() + 1;
        while (steps < limit) : (steps += 1) {
            cursor = self.edges.get(cursor) orelse return cursor;
        }
        return cursor;
    }

    pub fn clear(self: *Delegation, a: []const u8) bool {
        if (self.edges.fetchRemove(a)) |removed| {
            self.allocator.free(removed.key);
            self.allocator.free(removed.value);
            return true;
        }
        return false;
    }

    fn wouldCycle(self: *const Delegation, a: []const u8, b: []const u8) bool {
        var cursor = b;
        var steps: usize = 0;
        const limit = self.edges.count() + 1;
        while (steps < limit) : (steps += 1) {
            if (std.mem.eql(u8, cursor, a)) return true;
            cursor = self.edges.get(cursor) orelse return false;
        }
        return true;
    }
};

const testing = std.testing;

test "resolve follows a delegate chain" {
    var delegation = Delegation.init(testing.allocator);
    defer delegation.deinit();

    try testing.expect(try delegation.setDelegate("alice", "bob"));
    try testing.expect(try delegation.setDelegate("bob", "carol"));

    try testing.expectEqualStrings("carol", delegation.resolve("alice"));
    try testing.expectEqualStrings("carol", delegation.resolve("bob"));
    try testing.expectEqualStrings("dave", delegation.resolve("dave"));
}

test "cycle guard rejects direct and indirect loops" {
    var delegation = Delegation.init(testing.allocator);
    defer delegation.deinit();

    try testing.expect(!try delegation.setDelegate("alice", "alice"));
    try testing.expect(try delegation.setDelegate("alice", "bob"));
    try testing.expect(try delegation.setDelegate("bob", "carol"));
    try testing.expect(!try delegation.setDelegate("carol", "alice"));
    try testing.expectEqualStrings("carol", delegation.resolve("alice"));
}

test "clear removes only existing edges" {
    var delegation = Delegation.init(testing.allocator);
    defer delegation.deinit();

    try testing.expect(try delegation.setDelegate("alice", "bob"));
    try testing.expect(delegation.clear("alice"));
    try testing.expect(!delegation.clear("alice"));
    try testing.expectEqualStrings("alice", delegation.resolve("alice"));
}

test "setDelegate replaces an existing edge" {
    var delegation = Delegation.init(testing.allocator);
    defer delegation.deinit();

    try testing.expect(try delegation.setDelegate("alice", "bob"));
    try testing.expect(try delegation.setDelegate("alice", "carol"));
    try testing.expectEqualStrings("carol", delegation.resolve("alice"));
    try testing.expect(try delegation.setDelegate("carol", "dave"));
    try testing.expectEqualStrings("dave", delegation.resolve("alice"));
}
