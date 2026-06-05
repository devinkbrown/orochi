const std = @import("std");

pub const Id = struct {
    replica: u64,
    seq: u64,

    pub const root: Id = .{ .replica = 0, .seq = 0 };

    pub fn eql(a: Id, b: Id) bool {
        return a.replica == b.replica and a.seq == b.seq;
    }

    pub fn isRoot(self: Id) bool {
        return self.eql(root);
    }

    fn lessThan(a: Id, b: Id) bool {
        if (a.replica != b.replica) return a.replica < b.replica;
        return a.seq < b.seq;
    }

    fn greaterThan(a: Id, b: Id) bool {
        return !a.eql(b) and b.lessThan(a);
    }
};

pub const InsertOp = struct {
    id: Id,
    left: Id,
    char: u8,
};

pub const DeleteOp = struct {
    id: Id,
};

pub const Op = union(enum) {
    insert: InsertOp,
    delete: DeleteOp,
};

pub const Error = error{
    IndexOutOfBounds,
};

const Node = struct {
    id: Id,
    left: Id,
    char: u8,
    tombstone: bool,
};

pub const CrdtText = struct {
    nodes: std.ArrayList(Node) = .empty,
    pending_inserts: std.ArrayList(InsertOp) = .empty,
    pending_deletes: std.ArrayList(Id) = .empty,

    pub fn init() CrdtText {
        return .{};
    }

    pub fn deinit(self: *CrdtText, allocator: std.mem.Allocator) void {
        self.nodes.deinit(allocator);
        self.pending_inserts.deinit(allocator);
        self.pending_deletes.deinit(allocator);
        self.* = .{};
    }

    pub fn localInsert(
        self: *CrdtText,
        allocator: std.mem.Allocator,
        pos: usize,
        char: u8,
        replica: u64,
    ) !Op {
        const left = try self.leftOriginForPosition(pos);
        const op: Op = .{ .insert = .{
            .id = .{ .replica = replica, .seq = self.nextSeq(replica) },
            .left = left,
            .char = char,
        } };
        try self.applyRemote(allocator, op);
        return op;
    }

    pub fn localDelete(self: *CrdtText, pos: usize) !Op {
        const index = try self.visibleIndex(pos);
        self.nodes.items[index].tombstone = true;
        return .{ .delete = .{ .id = self.nodes.items[index].id } };
    }

    pub fn applyRemote(self: *CrdtText, allocator: std.mem.Allocator, op: Op) !void {
        switch (op) {
            .insert => |insert| {
                if (self.hasNode(insert.id)) return;
                if (!self.originExists(insert.left)) {
                    try self.rememberPendingInsert(allocator, insert);
                    return;
                }
                try self.insertKnown(allocator, insert);
                try self.drainPendingInserts(allocator);
            },
            .delete => |delete| {
                if (self.findNodeIndex(delete.id)) |index| {
                    self.nodes.items[index].tombstone = true;
                } else {
                    try self.rememberPendingDelete(allocator, delete.id);
                }
            },
        }
    }

    pub fn text(self: *const CrdtText, allocator: std.mem.Allocator) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);

        for (self.nodes.items) |node| {
            if (!node.tombstone) try out.append(allocator, node.char);
        }

        return out.toOwnedSlice(allocator);
    }

    pub fn visibleLen(self: *const CrdtText) usize {
        var count: usize = 0;
        for (self.nodes.items) |node| {
            if (!node.tombstone) count += 1;
        }
        return count;
    }

    fn nextSeq(self: *const CrdtText, replica: u64) u64 {
        var max: u64 = 0;

        for (self.nodes.items) |node| {
            if (node.id.replica == replica and node.id.seq > max) max = node.id.seq;
        }
        for (self.pending_inserts.items) |insert| {
            if (insert.id.replica == replica and insert.id.seq > max) max = insert.id.seq;
        }

        return max + 1;
    }

    fn leftOriginForPosition(self: *const CrdtText, pos: usize) !Id {
        if (pos == 0) return Id.root;
        const index = try self.visibleIndex(pos - 1);
        return self.nodes.items[index].id;
    }

    fn visibleIndex(self: *const CrdtText, pos: usize) !usize {
        var visible_pos: usize = 0;
        for (self.nodes.items, 0..) |node, index| {
            if (node.tombstone) continue;
            if (visible_pos == pos) return index;
            visible_pos += 1;
        }
        return Error.IndexOutOfBounds;
    }

    fn insertKnown(self: *CrdtText, allocator: std.mem.Allocator, insert: InsertOp) !void {
        if (self.hasNode(insert.id)) return;

        const node: Node = .{
            .id = insert.id,
            .left = insert.left,
            .char = insert.char,
            .tombstone = self.consumePendingDelete(insert.id),
        };

        const index = self.insertionIndex(insert.left, insert.id);
        try self.nodes.insert(allocator, index, node);
    }

    fn drainPendingInserts(self: *CrdtText, allocator: std.mem.Allocator) !void {
        var progressed = true;
        while (progressed) {
            progressed = false;
            var i: usize = 0;
            while (i < self.pending_inserts.items.len) {
                const insert = self.pending_inserts.items[i];
                if (!self.originExists(insert.left)) {
                    i += 1;
                    continue;
                }

                _ = self.pending_inserts.orderedRemove(i);
                try self.insertKnown(allocator, insert);
                progressed = true;
            }
        }
    }

    fn rememberPendingInsert(
        self: *CrdtText,
        allocator: std.mem.Allocator,
        insert: InsertOp,
    ) !void {
        for (self.pending_inserts.items) |existing| {
            if (existing.id.eql(insert.id)) return;
        }
        try self.pending_inserts.append(allocator, insert);
    }

    fn rememberPendingDelete(
        self: *CrdtText,
        allocator: std.mem.Allocator,
        id: Id,
    ) !void {
        for (self.pending_deletes.items) |existing| {
            if (existing.eql(id)) return;
        }
        try self.pending_deletes.append(allocator, id);
    }

    fn consumePendingDelete(self: *CrdtText, id: Id) bool {
        var found = false;
        var i: usize = 0;
        while (i < self.pending_deletes.items.len) {
            if (self.pending_deletes.items[i].eql(id)) {
                _ = self.pending_deletes.orderedRemove(i);
                found = true;
            } else {
                i += 1;
            }
        }
        return found;
    }

    fn insertionIndex(self: *const CrdtText, left: Id, id: Id) usize {
        var index = if (left.isRoot()) 0 else (self.findNodeIndex(left).? + 1);

        while (index < self.nodes.items.len) {
            const node = self.nodes.items[index];
            if (node.left.eql(left)) {
                if (node.id.greaterThan(id)) {
                    index = self.subtreeEnd(index);
                    continue;
                }
                break;
            }

            if (!self.isDescendantOf(node.id, left)) break;
            index += 1;
        }

        return index;
    }

    fn subtreeEnd(self: *const CrdtText, start: usize) usize {
        const ancestor = self.nodes.items[start].id;
        var index = start + 1;
        while (index < self.nodes.items.len and self.isDescendantOf(self.nodes.items[index].id, ancestor)) {
            index += 1;
        }
        return index;
    }

    fn isDescendantOf(self: *const CrdtText, id: Id, ancestor: Id) bool {
        if (ancestor.isRoot()) return true;

        var current = id;
        while (self.findNodeIndex(current)) |index| {
            const parent = self.nodes.items[index].left;
            if (parent.eql(ancestor)) return true;
            if (parent.isRoot()) return false;
            current = parent;
        }
        return false;
    }

    fn originExists(self: *const CrdtText, id: Id) bool {
        return id.isRoot() or self.hasNode(id);
    }

    fn hasNode(self: *const CrdtText, id: Id) bool {
        return self.findNodeIndex(id) != null;
    }

    fn findNodeIndex(self: *const CrdtText, id: Id) ?usize {
        for (self.nodes.items, 0..) |node, index| {
            if (node.id.eql(id)) return index;
        }
        return null;
    }
};

pub const Document = CrdtText;

fn expectText(doc: *const CrdtText, expected: []const u8) !void {
    const allocator = std.testing.allocator;
    const actual = try doc.text(allocator);
    defer allocator.free(actual);
    try std.testing.expectEqualStrings(expected, actual);
}

test "concurrent inserts at same position converge commutatively" {
    const allocator = std.testing.allocator;

    var a = CrdtText.init();
    defer a.deinit(allocator);
    var b = CrdtText.init();
    defer b.deinit(allocator);

    const a_op = try a.localInsert(allocator, 0, 'a', 1);
    const b_op = try b.localInsert(allocator, 0, 'b', 2);

    try a.applyRemote(allocator, b_op);
    try b.applyRemote(allocator, a_op);

    try expectText(&a, "ba");
    try expectText(&b, "ba");
}

test "delete tombstones without removing causal position" {
    const allocator = std.testing.allocator;

    var a = CrdtText.init();
    defer a.deinit(allocator);
    var b = CrdtText.init();
    defer b.deinit(allocator);

    const x = try a.localInsert(allocator, 0, 'x', 1);
    const y = try a.localInsert(allocator, 1, 'y', 1);
    const z = try a.localInsert(allocator, 2, 'z', 1);
    try b.applyRemote(allocator, x);
    try b.applyRemote(allocator, y);
    try b.applyRemote(allocator, z);

    const del = try a.localDelete(1);
    try b.applyRemote(allocator, del);

    try std.testing.expect(a.nodes.items[1].tombstone);
    try std.testing.expect(b.nodes.items[1].tombstone);
    try expectText(&a, "xz");
    try expectText(&b, "xz");

    const after_y = try b.localInsert(allocator, 1, '!', 2);
    try a.applyRemote(allocator, after_y);

    try expectText(&a, "x!z");
    try expectText(&b, "x!z");
}

test "dependent insert delivered before origin is retained and converges" {
    const allocator = std.testing.allocator;

    var source = CrdtText.init();
    defer source.deinit(allocator);
    var target = CrdtText.init();
    defer target.deinit(allocator);

    const h = try source.localInsert(allocator, 0, 'h', 1);
    const i = try source.localInsert(allocator, 1, 'i', 1);

    try target.applyRemote(allocator, i);
    try expectText(&target, "");
    try std.testing.expectEqual(@as(usize, 1), target.pending_inserts.items.len);

    try target.applyRemote(allocator, h);
    try expectText(&target, "hi");
    try std.testing.expectEqual(@as(usize, 0), target.pending_inserts.items.len);
}

test "interleaving converges regardless of remote apply order" {
    const allocator = std.testing.allocator;

    var left = CrdtText.init();
    defer left.deinit(allocator);
    var right = CrdtText.init();
    defer right.deinit(allocator);
    var order_one = CrdtText.init();
    defer order_one.deinit(allocator);
    var order_two = CrdtText.init();
    defer order_two.deinit(allocator);

    const l0 = try left.localInsert(allocator, 0, 'A', 1);
    const l1 = try left.localInsert(allocator, 1, 'B', 1);

    try right.applyRemote(allocator, l0);
    const r0 = try right.localInsert(allocator, 1, 'x', 2);
    const r1 = try right.localInsert(allocator, 2, 'y', 2);

    const ops = [_]Op{ l0, l1, r0, r1 };

    for (ops) |op| try order_one.applyRemote(allocator, op);
    try order_two.applyRemote(allocator, r1);
    try order_two.applyRemote(allocator, l1);
    try order_two.applyRemote(allocator, r0);
    try order_two.applyRemote(allocator, l0);

    try expectText(&left, "AB");
    try expectText(&right, "Axy");
    try expectText(&order_one, "AxyB");
    try expectText(&order_two, "AxyB");
}

test "deterministic ordering uses descending ids after the same origin" {
    const allocator = std.testing.allocator;

    var doc = CrdtText.init();
    defer doc.deinit(allocator);

    try doc.applyRemote(allocator, .{ .insert = .{
        .id = .{ .replica = 1, .seq = 1 },
        .left = Id.root,
        .char = 'a',
    } });
    try doc.applyRemote(allocator, .{ .insert = .{
        .id = .{ .replica = 3, .seq = 1 },
        .left = Id.root,
        .char = 'c',
    } });
    try doc.applyRemote(allocator, .{ .insert = .{
        .id = .{ .replica = 2, .seq = 1 },
        .left = Id.root,
        .char = 'b',
    } });

    try expectText(&doc, "cba");
}

test "remote delete before insert tombstones when insert arrives" {
    const allocator = std.testing.allocator;

    var doc = CrdtText.init();
    defer doc.deinit(allocator);

    const id: Id = .{ .replica = 7, .seq = 1 };
    try doc.applyRemote(allocator, .{ .delete = .{ .id = id } });
    try std.testing.expectEqual(@as(usize, 1), doc.pending_deletes.items.len);

    try doc.applyRemote(allocator, .{ .insert = .{
        .id = id,
        .left = Id.root,
        .char = 'x',
    } });

    try expectText(&doc, "");
    try std.testing.expectEqual(@as(usize, 0), doc.pending_deletes.items.len);
    try std.testing.expect(doc.nodes.items[0].tombstone);
}
