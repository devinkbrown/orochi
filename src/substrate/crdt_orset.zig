const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Dot = struct {
    replica: u64,
    counter: u64,
};

pub const OrSet = struct {
    const Self = @This();
    const AddMap = std.AutoHashMap(Dot, u64);
    const RemoveMap = std.AutoHashMap(Dot, void);
    const CounterMap = std.AutoHashMap(u64, u64);

    adds: AddMap,
    removes: RemoveMap,
    counters: CounterMap,

    pub fn init(allocator: Allocator) Self {
        return .{
            .adds = AddMap.init(allocator),
            .removes = RemoveMap.init(allocator),
            .counters = CounterMap.init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.adds.deinit();
        self.removes.deinit();
        self.counters.deinit();
        self.* = undefined;
    }

    pub fn add(self: *Self, elem: u64, replica: u64) !Dot {
        const next = (self.counters.get(replica) orelse 0) + 1;
        const dot = Dot{
            .replica = replica,
            .counter = next,
        };

        try self.adds.put(dot, elem);
        try self.counters.put(replica, next);
        return dot;
    }

    pub fn remove(self: *Self, elem: u64) !void {
        var it = self.adds.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* == elem) {
                try self.removes.put(entry.key_ptr.*, {});
            }
        }
    }

    pub fn merge(self: *Self, other: Self) !void {
        var add_it = other.adds.iterator();
        while (add_it.next()) |entry| {
            try self.adds.put(entry.key_ptr.*, entry.value_ptr.*);
            try self.bumpCounter(entry.key_ptr.*);
        }

        var remove_it = other.removes.iterator();
        while (remove_it.next()) |entry| {
            try self.removes.put(entry.key_ptr.*, {});
            try self.bumpCounter(entry.key_ptr.*);
        }

        var counter_it = other.counters.iterator();
        while (counter_it.next()) |entry| {
            const replica = entry.key_ptr.*;
            const counter = entry.value_ptr.*;
            if ((self.counters.get(replica) orelse 0) < counter) {
                try self.counters.put(replica, counter);
            }
        }
    }

    pub fn contains(self: Self, elem: u64) bool {
        var it = self.adds.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* == elem and !self.removes.contains(entry.key_ptr.*)) {
                return true;
            }
        }
        return false;
    }

    pub fn observedDotCount(self: Self, elem: u64) usize {
        var count: usize = 0;
        var it = self.adds.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* == elem and !self.removes.contains(entry.key_ptr.*)) {
                count += 1;
            }
        }
        return count;
    }

    pub fn addCount(self: Self) usize {
        return self.adds.count();
    }

    pub fn removeCount(self: Self) usize {
        return self.removes.count();
    }

    pub fn eql(self: Self, other: Self) bool {
        if (self.adds.count() != other.adds.count()) return false;
        if (self.removes.count() != other.removes.count()) return false;
        if (self.counters.count() != other.counters.count()) return false;

        var add_it = self.adds.iterator();
        while (add_it.next()) |entry| {
            if (other.adds.get(entry.key_ptr.*) != entry.value_ptr.*) return false;
        }

        var remove_it = self.removes.iterator();
        while (remove_it.next()) |entry| {
            if (!other.removes.contains(entry.key_ptr.*)) return false;
        }

        var counter_it = self.counters.iterator();
        while (counter_it.next()) |entry| {
            if (other.counters.get(entry.key_ptr.*) != entry.value_ptr.*) return false;
        }

        return true;
    }

    fn bumpCounter(self: *Self, dot: Dot) !void {
        const current = self.counters.get(dot.replica) orelse 0;
        if (current < dot.counter) {
            try self.counters.put(dot.replica, dot.counter);
        }
    }
};

fn cloneSet(allocator: Allocator, source: OrSet) !OrSet {
    var out = OrSet.init(allocator);
    errdefer out.deinit();
    try out.merge(source);
    return out;
}

test "add remove and re-add semantics" {
    const allocator = std.testing.allocator;
    var set = OrSet.init(allocator);
    defer set.deinit();

    const first = try set.add(42, 7);
    try std.testing.expectEqual(Dot{ .replica = 7, .counter = 1 }, first);
    try std.testing.expect(set.contains(42));

    try set.remove(42);
    try std.testing.expect(!set.contains(42));
    try std.testing.expectEqual(@as(usize, 1), set.removeCount());

    const second = try set.add(42, 7);
    try std.testing.expectEqual(Dot{ .replica = 7, .counter = 2 }, second);
    try std.testing.expect(set.contains(42));
    try std.testing.expectEqual(@as(usize, 1), set.observedDotCount(42));

    try set.remove(42);
    try std.testing.expect(!set.contains(42));
    try std.testing.expectEqual(@as(usize, 2), set.removeCount());
}

test "add wins against concurrent remove" {
    const allocator = std.testing.allocator;
    var add_side = OrSet.init(allocator);
    defer add_side.deinit();
    var remove_side = OrSet.init(allocator);
    defer remove_side.deinit();

    _ = try add_side.add(9, 1);
    try remove_side.remove(9);

    try add_side.merge(remove_side);
    try remove_side.merge(add_side);

    try std.testing.expect(add_side.contains(9));
    try std.testing.expect(remove_side.contains(9));
    try std.testing.expect(add_side.eql(remove_side));
}

test "merge is commutative and idempotent" {
    const allocator = std.testing.allocator;
    var a = OrSet.init(allocator);
    defer a.deinit();
    var b = OrSet.init(allocator);
    defer b.deinit();

    _ = try a.add(1, 10);
    _ = try a.add(2, 10);
    try a.remove(1);
    _ = try b.add(1, 20);
    _ = try b.add(3, 20);

    var ab = try cloneSet(allocator, a);
    defer ab.deinit();
    try ab.merge(b);

    var ba = try cloneSet(allocator, b);
    defer ba.deinit();
    try ba.merge(a);

    try std.testing.expect(ab.eql(ba));
    try std.testing.expect(ab.contains(1));
    try std.testing.expect(ab.contains(2));
    try std.testing.expect(ab.contains(3));

    const before_adds = ab.addCount();
    const before_removes = ab.removeCount();
    try ab.merge(ab);
    try std.testing.expectEqual(before_adds, ab.addCount());
    try std.testing.expectEqual(before_removes, ab.removeCount());
    try std.testing.expect(ab.eql(ba));
}

test "concurrent adds of same element both survive until removed" {
    const allocator = std.testing.allocator;
    var a = OrSet.init(allocator);
    defer a.deinit();
    var b = OrSet.init(allocator);
    defer b.deinit();

    const dot_a = try a.add(5, 1);
    const dot_b = try b.add(5, 2);
    try std.testing.expect(dot_a.replica != dot_b.replica);

    try a.merge(b);
    try std.testing.expect(a.contains(5));
    try std.testing.expectEqual(@as(usize, 2), a.observedDotCount(5));

    try a.remove(5);
    try std.testing.expect(!a.contains(5));
    try std.testing.expectEqual(@as(usize, 0), a.observedDotCount(5));
    try std.testing.expectEqual(@as(usize, 2), a.removeCount());
}

test "remove only tombstones observed dots" {
    const allocator = std.testing.allocator;
    var a = OrSet.init(allocator);
    defer a.deinit();
    var b = OrSet.init(allocator);
    defer b.deinit();

    _ = try a.add(77, 1);
    _ = try b.add(77, 2);
    try a.remove(77);

    try a.merge(b);
    try std.testing.expect(a.contains(77));
    try std.testing.expectEqual(@as(usize, 1), a.observedDotCount(77));

    try a.remove(77);
    try std.testing.expect(!a.contains(77));
    try std.testing.expectEqual(@as(usize, 2), a.removeCount());
}

test "merge carries counters forward for deterministic future dots" {
    const allocator = std.testing.allocator;
    var a = OrSet.init(allocator);
    defer a.deinit();
    var b = OrSet.init(allocator);
    defer b.deinit();

    _ = try b.add(1, 44);
    _ = try b.add(2, 44);
    try a.merge(b);

    const next = try a.add(3, 44);
    try std.testing.expectEqual(Dot{ .replica = 44, .counter = 3 }, next);
    try std.testing.expect(a.contains(1));
    try std.testing.expect(a.contains(2));
    try std.testing.expect(a.contains(3));
}

test "operations are deterministic across equal histories" {
    const allocator = std.testing.allocator;
    var a = OrSet.init(allocator);
    defer a.deinit();
    var b = OrSet.init(allocator);
    defer b.deinit();

    _ = try a.add(10, 1);
    _ = try b.add(10, 1);
    _ = try a.add(20, 1);
    _ = try b.add(20, 1);
    try a.remove(10);
    try b.remove(10);
    const a_dot = try a.add(10, 1);
    const b_dot = try b.add(10, 1);

    try std.testing.expectEqual(a_dot, b_dot);
    try std.testing.expect(a.eql(b));
    try std.testing.expect(a.contains(10));
    try std.testing.expect(!a.contains(30));
}

test "different elements with same replica get unique dots" {
    const allocator = std.testing.allocator;
    var set = OrSet.init(allocator);
    defer set.deinit();

    const a = try set.add(100, 1);
    const b = try set.add(200, 1);
    const c = try set.add(100, 1);

    try std.testing.expectEqual(Dot{ .replica = 1, .counter = 1 }, a);
    try std.testing.expectEqual(Dot{ .replica = 1, .counter = 2 }, b);
    try std.testing.expectEqual(Dot{ .replica = 1, .counter = 3 }, c);
    try std.testing.expectEqual(@as(usize, 2), set.observedDotCount(100));
    try std.testing.expectEqual(@as(usize, 1), set.observedDotCount(200));
}
