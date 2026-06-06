//! Parent-to-children message index for threaded replies.
//!
//! `children` returns a borrowed insertion-order view that remains valid until
//! the next mutation of the index.
const std = @import("std");

pub const ThreadIndex = struct {
    pub const max_parents: usize = 4096;
    pub const max_children_per_parent: usize = 256;
    pub const max_msgid_len: usize = 128;

    pub const Error = std.mem.Allocator.Error || error{
        ParentTooLong,
        ChildTooLong,
        TooManyParents,
        TooManyChildren,
    };

    allocator: std.mem.Allocator,
    parents: std.StringHashMap(ChildList),

    pub fn init(allocator: std.mem.Allocator) ThreadIndex {
        return .{
            .allocator = allocator,
            .parents = std.StringHashMap(ChildList).init(allocator),
        };
    }

    pub fn deinit(self: *ThreadIndex) void {
        var it = self.parents.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.parents.deinit();
        self.* = undefined;
    }

    pub fn addReply(self: *ThreadIndex, parent: []const u8, child: []const u8) Error!void {
        if (parent.len > max_msgid_len) return error.ParentTooLong;
        if (child.len > max_msgid_len) return error.ChildTooLong;

        const list = try self.ensureParent(parent);
        if (list.contains(child)) return;
        if (list.items.items.len >= max_children_per_parent) return error.TooManyChildren;

        const owned_child = try self.allocator.dupe(u8, child);
        errdefer self.allocator.free(owned_child);

        try list.items.append(self.allocator, owned_child);
    }

    pub fn children(self: *const ThreadIndex, parent: []const u8) []const []const u8 {
        const list = self.parents.getPtr(parent) orelse return &.{};
        return list.items.items;
    }

    pub fn clear(self: *ThreadIndex, parent: []const u8) bool {
        const removed = self.parents.fetchRemove(parent) orelse return false;
        self.allocator.free(removed.key);
        var list = removed.value;
        list.deinit(self.allocator);
        return true;
    }

    pub fn parentCount(self: *const ThreadIndex) usize {
        return self.parents.count();
    }

    fn ensureParent(self: *ThreadIndex, parent: []const u8) Error!*ChildList {
        if (self.parents.getPtr(parent)) |list| return list;
        if (self.parents.count() >= max_parents) return error.TooManyParents;

        const owned_parent = try self.allocator.dupe(u8, parent);
        errdefer self.allocator.free(owned_parent);

        try self.parents.putNoClobber(owned_parent, .{});
        return self.parents.getPtr(parent).?;
    }
};

const ChildList = struct {
    items: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *ChildList, allocator: std.mem.Allocator) void {
        for (self.items.items) |child| allocator.free(child);
        self.items.deinit(allocator);
        self.* = undefined;
    }

    fn contains(self: *const ChildList, child: []const u8) bool {
        for (self.items.items) |known| {
            if (std.mem.eql(u8, known, child)) return true;
        }
        return false;
    }
};

const testing = std.testing;

test "children are returned in insertion order" {
    var index = ThreadIndex.init(testing.allocator);
    defer index.deinit();

    try index.addReply("p1", "c1");
    try index.addReply("p1", "c2");
    try index.addReply("p1", "c3");

    const kids = index.children("p1");
    try testing.expectEqual(@as(usize, 3), kids.len);
    try testing.expectEqualStrings("c1", kids[0]);
    try testing.expectEqualStrings("c2", kids[1]);
    try testing.expectEqualStrings("c3", kids[2]);
}

test "duplicate child ids are ignored" {
    var index = ThreadIndex.init(testing.allocator);
    defer index.deinit();

    try index.addReply("p1", "c1");
    try index.addReply("p1", "c1");

    const kids = index.children("p1");
    try testing.expectEqual(@as(usize, 1), kids.len);
    try testing.expectEqualStrings("c1", kids[0]);
}

test "clear removes a parent and its children" {
    var index = ThreadIndex.init(testing.allocator);
    defer index.deinit();

    try index.addReply("p1", "c1");

    try testing.expect(index.clear("p1"));
    try testing.expect(!index.clear("p1"));
    try testing.expectEqual(@as(usize, 0), index.children("p1").len);
    try testing.expectEqual(@as(usize, 0), index.parentCount());
}

test "per-parent child cap is enforced" {
    var index = ThreadIndex.init(testing.allocator);
    defer index.deinit();

    for (0..ThreadIndex.max_children_per_parent) |i| {
        var child_buf: [32]u8 = undefined;
        const child = try std.fmt.bufPrint(child_buf[0..], "c-{d}", .{i});
        try index.addReply("p1", child);
    }

    try testing.expectError(error.TooManyChildren, index.addReply("p1", "overflow"));
    try testing.expectEqual(@as(usize, ThreadIndex.max_children_per_parent), index.children("p1").len);
}
