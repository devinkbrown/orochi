// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure operation-based sequence CRDT using an event-graph walk.
//!
//! Insert operations form a DAG-shaped log with a structural `after` edge and
//! causal parent heads. The materialized sequence is a deterministic FugueMax
//! walk over insert edges; deletes tombstone one insert without moving children.
const std = @import("std");

const Allocator = std.mem.Allocator;

var next_auto_agent = std.atomic.Value(u64).init(1);

pub const Id = struct {
    agent: u64,
    seq: u64,

    pub fn eql(a: Id, b: Id) bool {
        return a.agent == b.agent and a.seq == b.seq;
    }

    pub fn lessThan(_: void, a: Id, b: Id) bool {
        if (a.agent != b.agent) return a.agent < b.agent;
        return a.seq < b.seq;
    }

    pub fn greaterThan(_: void, a: Id, b: Id) bool {
        return lessThan({}, b, a);
    }
};

pub fn Document(comptime Value: type) type {
    return struct {
        const Self = @This();

        pub const Item = Value;

        pub const Insert = struct {
            after: ?Id,
            item: Value,
        };

        pub const Delete = struct {
            target: Id,
        };

        pub const Content = union(enum) {
            insert: Insert,
            delete: Delete,
        };

        pub const Op = struct {
            id: Id,
            parents: []const Id,
            content: Content,
        };

        pub const Error = Allocator.Error || error{
            PositionOutOfBounds,
            SequenceOverflow,
            ConflictingOperationId,
        };

        const StoredOp = struct {
            op: Self.Op,
            parents_owned: []Id,
        };

        allocator: Allocator,
        agent: u64,
        next_seq: u64 = 1,
        ops: std.ArrayList(StoredOp) = .empty,
        materialized: std.ArrayList(Value) = .empty,
        materialized_ids: std.ArrayList(Id) = .empty,
        dirty: bool = true,

        pub fn init(allocator: Allocator) Self {
            const agent = next_auto_agent.fetchAdd(1, .monotonic);
            return initWithAgent(allocator, agent);
        }

        pub fn initWithAgent(allocator: Allocator, agent: u64) Self {
            return .{
                .allocator = allocator,
                .agent = agent,
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.ops.items) |*entry| {
                self.allocator.free(entry.parents_owned);
            }
            self.ops.deinit(self.allocator);
            self.materialized.deinit(self.allocator);
            self.materialized_ids.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn localInsert(self: *Self, pos: usize, item: Value) Error!Self.Op {
            try self.ensureMaterialized();
            if (pos > self.materialized_ids.items.len) return error.PositionOutOfBounds;

            const after: ?Id = if (pos == 0) null else self.materialized_ids.items[pos - 1];
            const id = try self.nextId();
            const parents = try self.currentHeadsOwned();
            errdefer self.allocator.free(parents);

            const op = Self.Op{
                .id = id,
                .parents = parents,
                .content = .{ .insert = .{ .after = after, .item = item } },
            };
            return self.addOwnedOp(op, parents);
        }

        pub fn localDelete(self: *Self, pos: usize) Error!Self.Op {
            try self.ensureMaterialized();
            if (pos >= self.materialized_ids.items.len) return error.PositionOutOfBounds;

            const id = try self.nextId();
            const parents = try self.currentHeadsOwned();
            errdefer self.allocator.free(parents);

            const op = Self.Op{
                .id = id,
                .parents = parents,
                .content = .{ .delete = .{ .target = self.materialized_ids.items[pos] } },
            };
            return self.addOwnedOp(op, parents);
        }

        pub fn merge(self: *Self, remote_ops: []const Self.Op) Error!void {
            for (remote_ops) |remote| {
                if (self.findOpIndex(remote.id)) |idx| {
                    if (!opsEqual(self.ops.items[idx].op, remote)) {
                        return error.ConflictingOperationId;
                    }
                    continue;
                }

                const parents = try self.allocator.dupe(Id, remote.parents);
                errdefer self.allocator.free(parents);
                sortIds(parents);

                const op = Self.Op{
                    .id = remote.id,
                    .parents = parents,
                    .content = remote.content,
                };
                _ = try self.addOwnedOp(op, parents);

                if (remote.id.agent == self.agent and remote.id.seq >= self.next_seq) {
                    if (remote.id.seq == std.math.maxInt(u64)) {
                        self.next_seq = remote.id.seq;
                    } else {
                        self.next_seq = remote.id.seq + 1;
                    }
                }
            }
        }

        pub fn items(self: *Self) Error![]const Value {
            try self.ensureMaterialized();
            return self.materialized.items;
        }

        pub fn len(self: *Self) Error!usize {
            try self.ensureMaterialized();
            return self.materialized.items.len;
        }

        pub fn opCount(self: *const Self) usize {
            return self.ops.items.len;
        }

        fn nextId(self: *Self) Error!Id {
            if (self.next_seq == std.math.maxInt(u64)) return error.SequenceOverflow;
            const id = Id{ .agent = self.agent, .seq = self.next_seq };
            self.next_seq += 1;
            return id;
        }

        fn addOwnedOp(self: *Self, op: Self.Op, parents: []Id) Error!Self.Op {
            try self.ops.append(self.allocator, .{
                .op = op,
                .parents_owned = parents,
            });
            self.dirty = true;
            return self.ops.items[self.ops.items.len - 1].op;
        }

        fn ensureMaterialized(self: *Self) Error!void {
            if (!self.dirty) return;
            self.materialized.clearRetainingCapacity();
            self.materialized_ids.clearRetainingCapacity();
            try self.walkAfter(null);
            self.dirty = false;
        }

        fn walkAfter(self: *Self, after: ?Id) Error!void {
            var children: std.ArrayList(usize) = .empty;
            defer children.deinit(self.allocator);

            for (self.ops.items, 0..) |entry, idx| {
                switch (entry.op.content) {
                    .insert => |insert| {
                        if (optionalIdEql(insert.after, after)) {
                            try children.append(self.allocator, idx);
                        }
                    },
                    .delete => {},
                }
            }

            std.mem.sort(usize, children.items, self, childGreater);

            for (children.items) |idx| {
                const op = self.ops.items[idx].op;
                if (!self.isDeleted(op.id)) {
                    try self.materialized.append(self.allocator, op.content.insert.item);
                    try self.materialized_ids.append(self.allocator, op.id);
                }
                try self.walkAfter(op.id);
            }
        }

        fn childGreater(self: *Self, a_idx: usize, b_idx: usize) bool {
            const a = self.ops.items[a_idx].op.id;
            const b = self.ops.items[b_idx].op.id;
            return Id.greaterThan({}, a, b);
        }

        fn isDeleted(self: *const Self, id: Id) bool {
            for (self.ops.items) |entry| {
                switch (entry.op.content) {
                    .delete => |del| if (Id.eql(del.target, id)) return true,
                    .insert => {},
                }
            }
            return false;
        }

        fn currentHeadsOwned(self: *Self) Error![]Id {
            var heads: std.ArrayList(Id) = .empty;
            errdefer heads.deinit(self.allocator);

            for (self.ops.items) |entry| {
                if (!self.isParentOfAny(entry.op.id)) {
                    try heads.append(self.allocator, entry.op.id);
                }
            }

            const owned = try heads.toOwnedSlice(self.allocator);
            sortIds(owned);
            return owned;
        }

        fn isParentOfAny(self: *const Self, id: Id) bool {
            for (self.ops.items) |entry| {
                for (entry.op.parents) |parent| {
                    if (Id.eql(parent, id)) return true;
                }
            }
            return false;
        }

        fn findOpIndex(self: *const Self, id: Id) ?usize {
            for (self.ops.items, 0..) |entry, idx| {
                if (Id.eql(entry.op.id, id)) return idx;
            }
            return null;
        }

        fn opsEqual(a: Self.Op, b: Self.Op) bool {
            if (!Id.eql(a.id, b.id)) return false;
            if (!parentsEqual(a.parents, b.parents)) return false;

            switch (a.content) {
                .insert => |ai| switch (b.content) {
                    .insert => |bi| {
                        return optionalIdEql(ai.after, bi.after) and std.meta.eql(ai.item, bi.item);
                    },
                    .delete => return false,
                },
                .delete => |ad| switch (b.content) {
                    .delete => |bd| return Id.eql(ad.target, bd.target),
                    .insert => return false,
                },
            }
        }

        fn parentsEqual(a: []const Id, b: []const Id) bool {
            if (a.len != b.len) return false;
            for (a) |left| {
                var found = false;
                for (b) |right| {
                    if (Id.eql(left, right)) {
                        found = true;
                        break;
                    }
                }
                if (!found) return false;
            }
            return true;
        }
    };
}

pub const Item = u64;
pub const Doc = Document(Item);
pub const Op = Doc.Op;

fn optionalIdEql(a: ?Id, b: ?Id) bool {
    if (a) |av| {
        if (b) |bv| return Id.eql(av, bv);
        return false;
    }
    return b == null;
}

fn sortIds(ids: []Id) void {
    std.mem.sort(Id, ids, {}, Id.lessThan);
}

fn expectItems(doc: *Doc, expected: []const Item) !void {
    try std.testing.expectEqualSlices(Item, expected, try doc.items());
}

test "two replicas insert concurrently then merge to identical order" {
    const allocator = std.testing.allocator;
    var left = Doc.initWithAgent(allocator, 1);
    defer left.deinit();
    var right = Doc.initWithAgent(allocator, 2);
    defer right.deinit();

    const left_op = try left.localInsert(0, 10);
    const right_op = try right.localInsert(0, 20);

    try left.merge(&.{right_op});
    try right.merge(&.{left_op});

    try std.testing.expectEqualSlices(Item, try left.items(), try right.items());
    try expectItems(&left, &.{ 20, 10 });
}

test "concurrent inserts at the same position do not interleave" {
    const allocator = std.testing.allocator;
    var left = Doc.initWithAgent(allocator, 1);
    defer left.deinit();
    var right = Doc.initWithAgent(allocator, 2);
    defer right.deinit();

    const left_a = try left.localInsert(0, 10);
    const left_b = try left.localInsert(1, 11);
    const right_a = try right.localInsert(0, 20);
    const right_b = try right.localInsert(1, 21);

    try left.merge(&.{ right_a, right_b });
    try right.merge(&.{ left_a, left_b });

    try std.testing.expectEqualSlices(Item, try left.items(), try right.items());
    try expectItems(&left, &.{ 20, 21, 10, 11 });
}

test "delete then concurrent insert keeps child content and converges" {
    const allocator = std.testing.allocator;
    var left = Doc.initWithAgent(allocator, 1);
    defer left.deinit();
    var right = Doc.initWithAgent(allocator, 2);
    defer right.deinit();

    const root = try left.localInsert(0, 10);
    try right.merge(&.{root});

    const del = try left.localDelete(0);
    const child = try right.localInsert(1, 20);

    try left.merge(&.{child});
    try right.merge(&.{del});

    try std.testing.expectEqualSlices(Item, try left.items(), try right.items());
    try expectItems(&left, &.{20});
}

test "idempotent re-merge does not duplicate operations" {
    const allocator = std.testing.allocator;
    var left = Doc.initWithAgent(allocator, 1);
    defer left.deinit();
    var right = Doc.initWithAgent(allocator, 2);
    defer right.deinit();

    const op = try left.localInsert(0, 10);

    try right.merge(&.{op});
    try right.merge(&.{op});
    try right.merge(&.{op});

    try expectItems(&right, &.{10});
    try std.testing.expectEqual(@as(usize, 1), right.opCount());
}
