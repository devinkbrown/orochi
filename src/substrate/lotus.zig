const std = @import("std");

pub const Cid = [32]u8;

pub const Event = struct {
    parents: []const Cid,
    payload: []const u8,
};

pub const InsertError = error{
    MissingParents,
    DuplicateCid,
    Cycle,
    OutOfMemory,
};

pub const DagError = InsertError || error{CorruptStore};

pub const Dag = struct {
    allocator: std.mem.Allocator,
    events: std.AutoHashMap(Cid, StoredEvent),
    last_missing: std.ArrayList(Cid),

    pub fn init(allocator: std.mem.Allocator) Dag {
        return .{
            .allocator = allocator,
            .events = std.AutoHashMap(Cid, StoredEvent).init(allocator),
            .last_missing = .empty,
        };
    }

    pub fn deinit(self: *Dag) void {
        var it = self.events.valueIterator();
        while (it.next()) |stored| stored.deinit(self.allocator);
        self.events.deinit();
        self.last_missing.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn insert(self: *Dag, ev: Event) InsertError!Cid {
        self.last_missing.items.len = 0;

        const cid = try computeCid(self.allocator, ev);
        if (self.events.contains(cid)) return error.DuplicateCid;
        try rejectSelfParent(cid, ev);

        for (ev.parents) |parent| {
            if (!self.events.contains(parent)) {
                try appendUniqueCid(&self.last_missing, self.allocator, parent);
            }
        }
        if (self.last_missing.items.len != 0) return error.MissingParents;

        var stored = try StoredEvent.copyCanonical(self.allocator, ev);
        errdefer stored.deinit(self.allocator);
        try self.events.put(cid, stored);
        return cid;
    }

    pub fn applyStreamed(self: *Dag, events: []const Event) InsertError!void {
        for (events) |ev| _ = try self.insert(ev);
    }

    pub fn getEvent(self: *const Dag, cid: Cid) ?Event {
        const stored = self.events.get(cid) orelse return null;
        return .{ .parents = stored.parents, .payload = stored.payload };
    }

    pub fn contains(self: *const Dag, cid: Cid) bool {
        return self.events.contains(cid);
    }

    pub fn count(self: *const Dag) usize {
        return self.events.count();
    }

    pub fn missingParents(self: *const Dag) []const Cid {
        return self.last_missing.items;
    }

    pub fn allCids(self: *const Dag) ![]Cid {
        var out: std.ArrayList(Cid) = .empty;
        errdefer out.deinit(self.allocator);

        var it = self.events.keyIterator();
        while (it.next()) |cid| try out.append(self.allocator, cid.*);

        std.mem.sort(Cid, out.items, {}, cidLess);
        return out.toOwnedSlice(self.allocator);
    }

    pub fn heads(self: *const Dag) ![]Cid {
        var has_child = std.AutoHashMap(Cid, void).init(self.allocator);
        defer has_child.deinit();

        var value_it = self.events.valueIterator();
        while (value_it.next()) |stored| {
            for (stored.parents) |parent| try has_child.put(parent, {});
        }

        var out: std.ArrayList(Cid) = .empty;
        errdefer out.deinit(self.allocator);

        var key_it = self.events.keyIterator();
        while (key_it.next()) |cid| {
            if (!has_child.contains(cid.*)) try out.append(self.allocator, cid.*);
        }

        std.mem.sort(Cid, out.items, {}, cidLess);
        return out.toOwnedSlice(self.allocator);
    }

    pub fn frontier(self: *const Dag) ![]Cid {
        return self.heads();
    }

    pub fn causalOrder(self: *const Dag) DagError![]Cid {
        const cids = try self.allCids();
        defer self.allocator.free(cids);

        var indegree = std.AutoHashMap(Cid, usize).init(self.allocator);
        defer indegree.deinit();

        for (cids) |cid| {
            const stored = self.events.get(cid) orelse return error.CorruptStore;
            try indegree.put(cid, stored.parents.len);
        }

        var ready: std.ArrayList(Cid) = .empty;
        defer ready.deinit(self.allocator);

        for (cids) |cid| {
            if (indegree.get(cid).? == 0) try ready.append(self.allocator, cid);
        }
        sortCidDesc(ready.items);

        var out: std.ArrayList(Cid) = .empty;
        errdefer out.deinit(self.allocator);

        while (ready.items.len != 0) {
            const last = ready.items.len - 1;
            const cid = ready.items[last];
            ready.items.len = last;
            try out.append(self.allocator, cid);

            for (cids) |candidate| {
                const child = self.events.get(candidate) orelse return error.CorruptStore;
                if (!hasParent(child.parents, cid)) continue;

                const slot = indegree.getPtr(candidate) orelse return error.CorruptStore;
                if (slot.* == 0) return error.Cycle;
                slot.* -= 1;
                if (slot.* == 0) {
                    try ready.append(self.allocator, candidate);
                    sortCidDesc(ready.items);
                }
            }
        }

        if (out.items.len != self.events.count()) return error.Cycle;
        return out.toOwnedSlice(self.allocator);
    }

    pub fn wantList(self: *const Dag, have_frontier: []const Cid) DagError![]Cid {
        var known = std.AutoHashMap(Cid, void).init(self.allocator);
        defer known.deinit();

        for (have_frontier) |cid| try self.markAncestors(cid, &known);

        const order = try self.causalOrder();
        defer self.allocator.free(order);

        var out: std.ArrayList(Cid) = .empty;
        errdefer out.deinit(self.allocator);

        for (order) |cid| {
            if (!known.contains(cid)) try out.append(self.allocator, cid);
        }

        return out.toOwnedSlice(self.allocator);
    }

    fn markAncestors(self: *const Dag, cid: Cid, known: *std.AutoHashMap(Cid, void)) !void {
        if (known.contains(cid)) return;
        const stored = self.events.get(cid) orelse return;

        try known.put(cid, {});
        for (stored.parents) |parent| try self.markAncestors(parent, known);
    }
};

const StoredEvent = struct {
    parents: []Cid,
    payload: []u8,

    fn copyCanonical(allocator: std.mem.Allocator, event: Event) !StoredEvent {
        const parents = try allocator.alloc(Cid, event.parents.len);
        errdefer allocator.free(parents);
        @memcpy(parents, event.parents);
        std.mem.sort(Cid, parents, {}, cidLess);

        const payload = try allocator.alloc(u8, event.payload.len);
        errdefer allocator.free(payload);
        @memcpy(payload, event.payload);

        return .{ .parents = parents, .payload = payload };
    }

    fn deinit(self: *StoredEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.parents);
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub fn cidFor(allocator: std.mem.Allocator, event: Event) !Cid {
    return computeCid(allocator, event);
}

fn computeCid(allocator: std.mem.Allocator, event: Event) !Cid {
    const sorted = try allocator.alloc(Cid, event.parents.len);
    defer allocator.free(sorted);

    @memcpy(sorted, event.parents);
    std.mem.sort(Cid, sorted, {}, cidLess);

    var hasher = std.crypto.hash.Blake3.init(.{});
    for (sorted) |parent| hasher.update(parent[0..]);
    hasher.update(event.payload);

    var out: Cid = undefined;
    hasher.final(out[0..]);
    return out;
}

fn appendUniqueCid(list: *std.ArrayList(Cid), allocator: std.mem.Allocator, cid: Cid) !void {
    if (!hasParent(list.items, cid)) try list.append(allocator, cid);
}

fn rejectSelfParent(cid: Cid, ev: Event) InsertError!void {
    if (hasParent(ev.parents, cid)) return error.Cycle;
}

fn hasParent(parents: []const Cid, cid: Cid) bool {
    for (parents) |parent| {
        if (cidEql(parent, cid)) return true;
    }
    return false;
}

fn cidEql(a: Cid, b: Cid) bool {
    return std.mem.eql(u8, a[0..], b[0..]);
}

fn cidLess(_: void, a: Cid, b: Cid) bool {
    return std.mem.order(u8, a[0..], b[0..]) == .lt;
}

fn cidGreater(_: void, a: Cid, b: Cid) bool {
    return std.mem.order(u8, a[0..], b[0..]) == .gt;
}

fn sortCidDesc(cids: []Cid) void {
    std.mem.sort(Cid, cids, {}, cidGreater);
}

fn expectContains(cids: []const Cid, cid: Cid) !void {
    try std.testing.expect(hasParent(cids, cid));
}

fn expectNotContains(cids: []const Cid, cid: Cid) !void {
    try std.testing.expect(!hasParent(cids, cid));
}

fn expectCidSetsEqual(a: []const Cid, b: []const Cid) !void {
    try std.testing.expectEqual(a.len, b.len);
    for (a) |cid| try expectContains(b, cid);
}

fn expectBefore(order: []const Cid, before: Cid, after: Cid) !void {
    var before_index: ?usize = null;
    var after_index: ?usize = null;

    for (order, 0..) |cid, index| {
        if (cidEql(cid, before)) before_index = index;
        if (cidEql(cid, after)) after_index = index;
    }

    try std.testing.expect(before_index != null);
    try std.testing.expect(after_index != null);
    try std.testing.expect(before_index.? < after_index.?);
}

fn streamFor(dag: *const Dag, cids: []const Cid, allocator: std.mem.Allocator) ![]Event {
    var out: std.ArrayList(Event) = .empty;
    errdefer out.deinit(allocator);

    for (cids) |cid| {
        const ev = dag.getEvent(cid) orelse return error.CorruptStore;
        try out.append(allocator, ev);
    }

    return out.toOwnedSlice(allocator);
}

test "small DAG has deterministic content addresses" {
    const allocator = std.testing.allocator;

    var dag = Dag.init(allocator);
    defer dag.deinit();

    const root = try dag.insert(.{ .parents = &.{}, .payload = "root" });
    const left = try dag.insert(.{ .parents = &.{root}, .payload = "left" });
    const right = try dag.insert(.{ .parents = &.{root}, .payload = "right" });
    const merge_a = try dag.insert(.{ .parents = &.{ left, right }, .payload = "merge" });

    var dag2 = Dag.init(allocator);
    defer dag2.deinit();

    const root2 = try dag2.insert(.{ .parents = &.{}, .payload = "root" });
    const right2 = try dag2.insert(.{ .parents = &.{root2}, .payload = "right" });
    const left2 = try dag2.insert(.{ .parents = &.{root2}, .payload = "left" });
    const merge_b = try dag2.insert(.{ .parents = &.{ right2, left2 }, .payload = "merge" });

    try std.testing.expect(cidEql(root, root2));
    try std.testing.expect(cidEql(left, left2));
    try std.testing.expect(cidEql(right, right2));
    try std.testing.expect(cidEql(merge_a, merge_b));
    try std.testing.expectEqual(@as(usize, 4), dag.count());
}

test "missing-parent rejection records the missing parents" {
    const allocator = std.testing.allocator;

    var dag = Dag.init(allocator);
    defer dag.deinit();

    const unknown = try cidFor(allocator, .{ .parents = &.{}, .payload = "missing" });

    try std.testing.expectError(
        error.MissingParents,
        dag.insert(.{ .parents = &.{unknown}, .payload = "child" }),
    );
    try std.testing.expectEqual(@as(usize, 1), dag.missingParents().len);
    try std.testing.expect(cidEql(unknown, dag.missingParents()[0]));
    try std.testing.expectEqual(@as(usize, 0), dag.count());
}

test "topological order respects causality" {
    const allocator = std.testing.allocator;

    var dag = Dag.init(allocator);
    defer dag.deinit();

    const root = try dag.insert(.{ .parents = &.{}, .payload = "root" });
    const a = try dag.insert(.{ .parents = &.{root}, .payload = "a" });
    const b = try dag.insert(.{ .parents = &.{root}, .payload = "b" });
    const c = try dag.insert(.{ .parents = &.{ a, b }, .payload = "c" });

    const order = try dag.causalOrder();
    defer allocator.free(order);

    try std.testing.expectEqual(@as(usize, 4), order.len);
    try expectBefore(order, root, a);
    try expectBefore(order, root, b);
    try expectBefore(order, a, c);
    try expectBefore(order, b, c);
}

test "frontier and heads report events with no children" {
    const allocator = std.testing.allocator;

    var dag = Dag.init(allocator);
    defer dag.deinit();

    const root = try dag.insert(.{ .parents = &.{}, .payload = "root" });
    const a = try dag.insert(.{ .parents = &.{root}, .payload = "a" });
    const b = try dag.insert(.{ .parents = &.{root}, .payload = "b" });

    const heads = try dag.heads();
    defer allocator.free(heads);
    const frontier = try dag.frontier();
    defer allocator.free(frontier);

    try std.testing.expectEqual(@as(usize, 2), heads.len);
    try expectContains(heads, a);
    try expectContains(heads, b);
    try expectNotContains(heads, root);
    try expectCidSetsEqual(heads, frontier);
}

test "backfill want-list computes the gap between replicas" {
    const allocator = std.testing.allocator;

    var source = Dag.init(allocator);
    defer source.deinit();
    var lagging = Dag.init(allocator);
    defer lagging.deinit();

    const root = try source.insert(.{ .parents = &.{}, .payload = "root" });
    const a = try source.insert(.{ .parents = &.{root}, .payload = "a" });
    const b = try source.insert(.{ .parents = &.{root}, .payload = "b" });
    const c = try source.insert(.{ .parents = &.{ a, b }, .payload = "c" });

    const lag_root = try lagging.insert(.{ .parents = &.{}, .payload = "root" });
    const lag_a = try lagging.insert(.{ .parents = &.{lag_root}, .payload = "a" });
    try std.testing.expect(cidEql(root, lag_root));
    try std.testing.expect(cidEql(a, lag_a));

    const have = try lagging.frontier();
    defer allocator.free(have);
    const want = try source.wantList(have);
    defer allocator.free(want);

    try std.testing.expectEqual(@as(usize, 2), want.len);
    try expectContains(want, b);
    try expectContains(want, c);
    try expectNotContains(want, root);
    try expectNotContains(want, a);
}

test "applyStreamed converges a lagging replica" {
    const allocator = std.testing.allocator;

    var source = Dag.init(allocator);
    defer source.deinit();
    var lagging = Dag.init(allocator);
    defer lagging.deinit();

    const root = try source.insert(.{ .parents = &.{}, .payload = "root" });
    const a = try source.insert(.{ .parents = &.{root}, .payload = "a" });
    const b = try source.insert(.{ .parents = &.{root}, .payload = "b" });
    const c = try source.insert(.{ .parents = &.{ a, b }, .payload = "c" });
    _ = c;

    _ = try lagging.insert(.{ .parents = &.{}, .payload = "root" });
    _ = try lagging.insert(.{ .parents = &.{root}, .payload = "a" });

    const have = try lagging.frontier();
    defer allocator.free(have);
    const want = try source.wantList(have);
    defer allocator.free(want);
    const streamed = try streamFor(&source, want, allocator);
    defer allocator.free(streamed);

    try lagging.applyStreamed(streamed);

    const source_cids = try source.allCids();
    defer allocator.free(source_cids);
    const lagging_cids = try lagging.allCids();
    defer allocator.free(lagging_cids);
    const source_frontier = try source.frontier();
    defer allocator.free(source_frontier);
    const lagging_frontier = try lagging.frontier();
    defer allocator.free(lagging_frontier);

    try expectCidSetsEqual(source_cids, lagging_cids);
    try expectCidSetsEqual(source_frontier, lagging_frontier);
}

test "out-of-causal-order stream is rejected" {
    const allocator = std.testing.allocator;

    var source = Dag.init(allocator);
    defer source.deinit();
    var lagging = Dag.init(allocator);
    defer lagging.deinit();

    const root = try source.insert(.{ .parents = &.{}, .payload = "root" });
    const child = try source.insert(.{ .parents = &.{root}, .payload = "child" });

    const bad_stream = [_]Event{
        source.getEvent(child).?,
        source.getEvent(root).?,
    };

    try std.testing.expectError(error.MissingParents, lagging.applyStreamed(&bad_stream));
    try std.testing.expectEqual(@as(usize, 0), lagging.count());
    try std.testing.expectEqual(@as(usize, 1), lagging.missingParents().len);
    try std.testing.expect(cidEql(root, lagging.missingParents()[0]));
}

test "duplicate cid and self-parent are rejected" {
    const allocator = std.testing.allocator;

    var dag = Dag.init(allocator);
    defer dag.deinit();

    const root = try dag.insert(.{ .parents = &.{}, .payload = "root" });
    try std.testing.expectError(
        error.DuplicateCid,
        dag.insert(.{ .parents = &.{}, .payload = "root" }),
    );

    try std.testing.expectError(error.Cycle, rejectSelfParent(root, .{ .parents = &.{root}, .payload = "self" }));
    try std.testing.expect(dag.contains(root));
}
