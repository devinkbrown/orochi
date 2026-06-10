const std = @import("std");
const Allocator = std.mem.Allocator;
const Blake3 = std.crypto.hash.Blake3;
pub const Key = [32]u8;
pub const Hash = [32]u8;
const boundary_bits: u6 = 5;
const max_leaf_keys = 64;
const min_fanout = 2;
const max_fanout = 64;
const empty_hash = hashEmpty();

const Child = struct {
    hash: Hash,
    min_key: Key,
    max_key: Key,
    level: u16,
    count: usize,
};

const Node = struct {
    hash: Hash,
    min_key: Key,
    max_key: Key,
    level: u16,
    count: usize,
    leaf_keys: []Key = &.{},
    children: []Child = &.{},
    fn view(self: *const Node) NodeView {
        return .{
            .hash = self.hash,
            .min_key = self.min_key,
            .max_key = self.max_key,
            .level = self.level,
            .count = self.count,
            .leaf_keys = self.leaf_keys,
            .children = self.children,
        };
    }
};

pub const NodeView = struct {
    hash: Hash,
    min_key: Key,
    max_key: Key,
    level: u16,
    count: usize,
    leaf_keys: []const Key,
    children: []const Child,
    fn isLeaf(self: NodeView) bool {
        return self.level == 0;
    }
};

pub const NodeFetcher = struct {
    ptr: *const anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        fetch: *const fn (ctx: *const anyopaque, hash: Hash) ?NodeView,
    };
    pub fn fetch(self: NodeFetcher, hash: Hash) ?NodeView {
        return self.vtable.fetch(self.ptr, hash);
    }
};

pub const DiffRange = struct {
    start: Key,
    end: Key,
};

pub const DiffResult = struct {
    allocator: Allocator,
    ranges: []DiffRange,

    pub fn deinit(self: *DiffResult) void {
        self.allocator.free(self.ranges);
        self.* = .{ .allocator = self.allocator, .ranges = &.{} };
    }
};

pub const Error = Allocator.Error || error{MissingNode};

pub const Tree = struct {
    allocator: Allocator,
    keys: std.ArrayList(Key) = .empty,
    nodes: std.AutoHashMap(Hash, Node),
    root_hash: Hash = empty_hash,

    pub fn init(allocator: Allocator) Tree {
        return .{
            .allocator = allocator,
            .nodes = std.AutoHashMap(Hash, Node).init(allocator),
        };
    }

    pub fn deinit(self: *Tree) void {
        self.keys.deinit(self.allocator);
        destroyNodeMap(self.allocator, &self.nodes);
        self.* = Tree.init(self.allocator);
    }

    pub fn insert(self: *Tree, key: Key) Error!void {
        const found = self.findKey(key);
        if (found.exists) return;
        try self.keys.insert(self.allocator, found.index, key);
        errdefer _ = self.keys.orderedRemove(found.index);
        try self.rebuild();
    }

    pub fn remove(self: *Tree, key: Key) Error!bool {
        const found = self.findKey(key);
        if (!found.exists) return false;
        const removed = self.keys.orderedRemove(found.index);
        errdefer self.keys.insert(self.allocator, found.index, removed) catch {};
        try self.rebuild();
        return true;
    }

    pub fn contains(self: *const Tree, key: Key) bool {
        return self.findKey(key).exists;
    }

    pub fn rootHash(self: *const Tree) Hash {
        return self.root_hash;
    }

    pub fn fetcher(self: *const Tree) NodeFetcher {
        return .{ .ptr = self, .vtable = &fetcher_vtable };
    }

    pub fn diff(self: *const Tree, allocator: Allocator, other: *const Tree) Error!DiffResult {
        return diffRoots(allocator, self.fetcher(), self.root_hash, other.fetcher(), other.root_hash);
    }

    fn rebuild(self: *Tree) Error!void {
        var new_nodes = std.AutoHashMap(Hash, Node).init(self.allocator);
        errdefer destroyNodeMap(self.allocator, &new_nodes);

        const new_root = try buildRoot(self.allocator, self.keys.items, &new_nodes);

        destroyNodeMap(self.allocator, &self.nodes);
        self.nodes = new_nodes;
        self.root_hash = new_root;
    }

    fn getNode(self: *const Tree, hash: Hash) ?NodeView {
        if (std.mem.eql(u8, &hash, &empty_hash)) return null;
        const node = self.nodes.getPtr(hash) orelse return null;
        return node.view();
    }

    const FindResult = struct { index: usize, exists: bool };

    fn findKey(self: *const Tree, key: Key) FindResult {
        var low: usize = 0;
        var high: usize = self.keys.items.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            switch (std.mem.order(u8, &self.keys.items[mid], &key)) {
                .lt => low = mid + 1,
                .eq => return .{ .index = mid, .exists = true },
                .gt => high = mid,
            }
        }
        return .{ .index = low, .exists = false };
    }

    fn fetchNode(ctx: *const anyopaque, hash: Hash) ?NodeView {
        const self: *const Tree = @ptrCast(@alignCast(ctx));
        return self.getNode(hash);
    }

    const fetcher_vtable = NodeFetcher.VTable{ .fetch = fetchNode };
};

pub fn diffRoots(
    allocator: Allocator,
    left: NodeFetcher,
    left_root: Hash,
    right: NodeFetcher,
    right_root: Hash,
) Error!DiffResult {
    var ranges: std.ArrayList(DiffRange) = .empty;
    errdefer ranges.deinit(allocator);

    try diffNodeHashes(allocator, left, left_root, right, right_root, &ranges);
    ranges.shrinkRetainingCapacity(coalesceRanges(ranges.items));
    return .{ .allocator = allocator, .ranges = try ranges.toOwnedSlice(allocator) };
}

fn buildRoot(allocator: Allocator, keys: []const Key, nodes: *std.AutoHashMap(Hash, Node)) Error!Hash {
    if (keys.len == 0) return empty_hash;

    var level_refs = try buildLeaves(allocator, keys, nodes);
    defer level_refs.deinit(allocator);

    var level: u16 = 1;
    while (level_refs.items.len > 1) : (level += 1) {
        const next = try buildParents(allocator, level, level_refs.items, nodes);
        level_refs.deinit(allocator);
        level_refs = next;
    }
    return level_refs.items[0].hash;
}

fn buildLeaves(allocator: Allocator, keys: []const Key, nodes: *std.AutoHashMap(Hash, Node)) Error!std.ArrayList(Child) {
    var refs: std.ArrayList(Child) = .empty;
    errdefer refs.deinit(allocator);

    var start: usize = 0;
    var i: usize = 1;
    while (i <= keys.len) : (i += 1) {
        const split = i == keys.len or
            (i > start and startsChunk(0, keys[i])) or
            (i - start >= max_leaf_keys);
        if (!split) continue;

        const owned = try allocator.dupe(Key, keys[start..i]);
        errdefer allocator.free(owned);
        const h = hashLeaf(owned);
        const node = Node{
            .hash = h,
            .min_key = owned[0],
            .max_key = owned[owned.len - 1],
            .level = 0,
            .count = owned.len,
            .leaf_keys = owned,
        };
        try nodes.put(h, node);
        try refs.append(allocator, nodeToChild(node));
        start = i;
    }
    return refs;
}

fn buildParents(
    allocator: Allocator,
    level: u16,
    refs: []const Child,
    nodes: *std.AutoHashMap(Hash, Node),
) Error!std.ArrayList(Child) {
    var out: std.ArrayList(Child) = .empty;
    errdefer out.deinit(allocator);

    var start: usize = 0;
    var i: usize = 1;
    while (i <= refs.len) : (i += 1) {
        const size = i - start;
        const split = i == refs.len or
            (size >= min_fanout and startsChunk(level, refs[i].min_key)) or
            (size >= max_fanout);
        if (!split) continue;

        const owned = try allocator.dupe(Child, refs[start..i]);
        errdefer allocator.free(owned);
        const h = hashInternal(level, owned);
        const node = Node{
            .hash = h,
            .min_key = owned[0].min_key,
            .max_key = owned[owned.len - 1].max_key,
            .level = level,
            .count = countChildren(owned),
            .children = owned,
        };
        try nodes.put(h, node);
        try out.append(allocator, nodeToChild(node));
        start = i;
    }
    return out;
}

fn diffNodeHashes(
    allocator: Allocator,
    left_fetcher: NodeFetcher,
    left_hash: Hash,
    right_fetcher: NodeFetcher,
    right_hash: Hash,
    out: *std.ArrayList(DiffRange),
) Error!void {
    if (std.mem.eql(u8, &left_hash, &right_hash)) return;

    const left = left_fetcher.fetch(left_hash);
    const right = right_fetcher.fetch(right_hash);
    if (left == null and right == null) return error.MissingNode;
    if (left == null) return appendRange(allocator, out, right.?.min_key, right.?.max_key);
    if (right == null) return appendRange(allocator, out, left.?.min_key, left.?.max_key);
    try diffViews(allocator, left_fetcher, left.?, right_fetcher, right.?, out);
}

fn diffViews(
    allocator: Allocator,
    left_fetcher: NodeFetcher,
    left: NodeView,
    right_fetcher: NodeFetcher,
    right: NodeView,
    out: *std.ArrayList(DiffRange),
) Error!void {
    if (std.mem.eql(u8, &left.hash, &right.hash)) return;
    if (left.isLeaf() and right.isLeaf()) return diffLeafKeys(allocator, left.leaf_keys, right.leaf_keys, out);
    if (left.level != right.level or left.isLeaf() or right.isLeaf()) {
        return diffSubtreeKeys(allocator, left_fetcher, left.hash, right_fetcher, right.hash, out);
    }

    var i: usize = 0;
    var j: usize = 0;
    while (i < left.children.len or j < right.children.len) {
        if (i >= left.children.len) {
            try appendRange(allocator, out, right.children[j].min_key, right.children[j].max_key);
            j += 1;
        } else if (j >= right.children.len) {
            try appendRange(allocator, out, left.children[i].min_key, left.children[i].max_key);
            i += 1;
        } else {
            const l = left.children[i];
            const r = right.children[j];
            if (std.mem.eql(u8, &l.hash, &r.hash)) {
                i += 1;
                j += 1;
            } else if (keyLess(l.max_key, r.min_key)) {
                try appendRange(allocator, out, l.min_key, l.max_key);
                i += 1;
            } else if (keyLess(r.max_key, l.min_key)) {
                try appendRange(allocator, out, r.min_key, r.max_key);
                j += 1;
            } else if (std.mem.eql(u8, &l.min_key, &r.min_key) and std.mem.eql(u8, &l.max_key, &r.max_key)) {
                try diffNodeHashes(allocator, left_fetcher, l.hash, right_fetcher, r.hash, out);
                i += 1;
                j += 1;
            } else {
                try diffSubtreeKeys(allocator, left_fetcher, l.hash, right_fetcher, r.hash, out);
                i += 1;
                j += 1;
            }
        }
    }
}

fn diffSubtreeKeys(
    allocator: Allocator,
    left_fetcher: NodeFetcher,
    left_hash: Hash,
    right_fetcher: NodeFetcher,
    right_hash: Hash,
    out: *std.ArrayList(DiffRange),
) Error!void {
    var left_keys: std.ArrayList(Key) = .empty;
    defer left_keys.deinit(allocator);
    var right_keys: std.ArrayList(Key) = .empty;
    defer right_keys.deinit(allocator);
    try collectKeys(allocator, left_fetcher, left_hash, &left_keys);
    try collectKeys(allocator, right_fetcher, right_hash, &right_keys);
    try diffLeafKeys(allocator, left_keys.items, right_keys.items, out);
}

fn collectKeys(allocator: Allocator, fetcher: NodeFetcher, hash: Hash, out: *std.ArrayList(Key)) Error!void {
    const node = fetcher.fetch(hash) orelse return error.MissingNode;
    if (node.isLeaf()) return out.appendSlice(allocator, node.leaf_keys);
    for (node.children) |child| try collectKeys(allocator, fetcher, child.hash, out);
}

fn diffLeafKeys(allocator: Allocator, left: []const Key, right: []const Key, out: *std.ArrayList(DiffRange)) Allocator.Error!void {
    var i: usize = 0;
    var j: usize = 0;
    while (i < left.len or j < right.len) {
        if (i >= left.len) {
            try appendRange(allocator, out, right[j], right[j]);
            j += 1;
        } else if (j >= right.len) {
            try appendRange(allocator, out, left[i], left[i]);
            i += 1;
        } else switch (std.mem.order(u8, &left[i], &right[j])) {
            .lt => {
                try appendRange(allocator, out, left[i], left[i]);
                i += 1;
            },
            .gt => {
                try appendRange(allocator, out, right[j], right[j]);
                j += 1;
            },
            .eq => {
                i += 1;
                j += 1;
            },
        }
    }
}

fn appendRange(allocator: Allocator, out: *std.ArrayList(DiffRange), start: Key, end: Key) Allocator.Error!void {
    try out.append(allocator, .{ .start = start, .end = end });
}

fn coalesceRanges(ranges: []DiffRange) usize {
    if (ranges.len < 2) return ranges.len;
    std.mem.sort(DiffRange, ranges, {}, rangeLess);
    var write: usize = 0;
    for (ranges[1..]) |range| {
        if (!keyLess(ranges[write].end, range.start)) {
            ranges[write].end = maxKey(ranges[write].end, range.end);
        } else {
            write += 1;
            ranges[write] = range;
        }
    }
    return write + 1;
}

fn rangeLess(_: void, a: DiffRange, b: DiffRange) bool {
    return keyLess(a.start, b.start);
}

fn nodeToChild(node: Node) Child {
    return .{
        .hash = node.hash,
        .min_key = node.min_key,
        .max_key = node.max_key,
        .level = node.level,
        .count = node.count,
    };
}

fn countChildren(children: []const Child) usize {
    var total: usize = 0;
    for (children) |child| total += child.count;
    return total;
}

fn startsChunk(level: u16, item: Key) bool {
    return trailingZeroBits(boundaryHash(level, item)) >= boundary_bits;
}

fn hashEmpty() Hash {
    @setEvalBranchQuota(5000);
    var h = Blake3.init(.{});
    h.update("orochi.suimyaku.prolly.empty.v1");
    var out: Hash = undefined;
    h.final(&out);
    return out;
}

fn hashLeaf(keys: []const Key) Hash {
    var h = Blake3.init(.{});
    h.update("orochi.suimyaku.prolly.leaf.v1");
    updateU64(&h, keys.len);
    for (keys) |item| h.update(&item);
    var out: Hash = undefined;
    h.final(&out);
    return out;
}

fn hashInternal(level: u16, children: []const Child) Hash {
    var h = Blake3.init(.{});
    h.update("orochi.suimyaku.prolly.node.v1");
    updateU16(&h, level);
    updateU64(&h, children.len);
    for (children) |child| {
        h.update(&child.hash);
        h.update(&child.min_key);
        h.update(&child.max_key);
        updateU64(&h, child.count);
    }
    var out: Hash = undefined;
    h.final(&out);
    return out;
}

fn boundaryHash(level: u16, item: Key) Hash {
    var h = Blake3.init(.{});
    h.update("orochi.suimyaku.prolly.boundary.v1");
    updateU16(&h, level);
    h.update(&item);
    var out: Hash = undefined;
    h.final(&out);
    return out;
}

fn updateU16(h: *Blake3, value: u16) void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .big);
    h.update(&buf);
}

fn updateU64(h: *Blake3, value: usize) void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, @intCast(value), .big);
    h.update(&buf);
}

fn trailingZeroBits(hash: Hash) u16 {
    var total: u16 = 0;
    var i: usize = hash.len;
    while (i > 0) {
        i -= 1;
        const byte = hash[i];
        if (byte == 0) {
            total += 8;
        } else {
            total += @ctz(byte);
            break;
        }
    }
    return total;
}

fn minKey(a: Key, b: Key) Key {
    return if (keyLess(a, b)) a else b;
}

fn maxKey(a: Key, b: Key) Key {
    return if (keyLess(a, b)) b else a;
}

fn keyLess(a: Key, b: Key) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

fn destroyNodeMap(allocator: Allocator, map: *std.AutoHashMap(Hash, Node)) void {
    var values = map.valueIterator();
    while (values.next()) |node| {
        allocator.free(node.leaf_keys);
        allocator.free(node.children);
    }
    map.deinit();
}

fn testKey(n: u8) Key {
    var out: Key = [_]u8{0} ** 32;
    out[31] = n;
    return out;
}

fn expectRange(range: DiffRange, start: u8, end: u8) !void {
    try std.testing.expectEqual(testKey(start), range.start);
    try std.testing.expectEqual(testKey(end), range.end);
}

test "same set in any insert order has identical root" {
    const allocator = std.testing.allocator;
    var a = Tree.init(allocator);
    defer a.deinit();
    var b = Tree.init(allocator);
    defer b.deinit();
    try a.insert(testKey(3));
    try a.insert(testKey(1));
    try a.insert(testKey(9));
    try a.insert(testKey(4));
    try b.insert(testKey(9));
    try b.insert(testKey(4));
    try b.insert(testKey(1));
    try b.insert(testKey(3));
    try std.testing.expectEqual(a.rootHash(), b.rootHash());
}

test "differing sets have different roots" {
    const allocator = std.testing.allocator;
    var a = Tree.init(allocator);
    defer a.deinit();
    var b = Tree.init(allocator);
    defer b.deinit();
    try a.insert(testKey(1));
    try a.insert(testKey(2));
    try b.insert(testKey(1));
    try b.insert(testKey(3));
    try std.testing.expect(!std.mem.eql(u8, &a.rootHash(), &b.rootHash()));
}

test "divergence localization returns differing key range" {
    const allocator = std.testing.allocator;
    var a = Tree.init(allocator);
    defer a.deinit();
    var b = Tree.init(allocator);
    defer b.deinit();
    var i: u8 = 1;
    while (i <= 12) : (i += 1) {
        try a.insert(testKey(i));
        try b.insert(testKey(i));
    }
    try b.insert(testKey(20));
    var diff = try a.diff(allocator, &b);
    defer diff.deinit();
    try std.testing.expectEqual(@as(usize, 1), diff.ranges.len);
    try expectRange(diff.ranges[0], 20, 20);
}

test "insert remove round trip and contains" {
    const allocator = std.testing.allocator;
    var tree = Tree.init(allocator);
    defer tree.deinit();
    try tree.insert(testKey(7));
    try tree.insert(testKey(8));
    const before = tree.rootHash();
    try std.testing.expect(tree.contains(testKey(7)));
    try tree.insert(testKey(9));
    try std.testing.expect(try tree.remove(testKey(9)));
    try std.testing.expect(!tree.contains(testKey(9)));
    try std.testing.expectEqual(before, tree.rootHash());
    try std.testing.expect(!try tree.remove(testKey(42)));
}
