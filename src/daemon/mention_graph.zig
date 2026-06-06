const std = @import("std");

pub const MentionTotal = struct {
    name: []const u8,
    count: u64,
};

pub const MentionGraph = struct {
    pub const Config = struct {
        max_sources: usize = 4096,
        max_targets_per_source: usize = 1024,
        max_mentioned: usize = 4096,
    };

    pub const Error = std.mem.Allocator.Error || error{ TooManySources, TooManyTargets, TooManyMentioned };

    const TargetCounts = struct {
        counts: std.StringHashMap(u32),

        fn init(allocator: std.mem.Allocator) TargetCounts {
            return .{ .counts = std.StringHashMap(u32).init(allocator) };
        }

        fn deinit(self: *TargetCounts, allocator: std.mem.Allocator) void {
            var it = self.counts.iterator();
            while (it.next()) |entry| allocator.free(entry.key_ptr.*);
            self.counts.deinit();
        }
    };

    allocator: std.mem.Allocator,
    cfg: Config,
    edges: std.StringHashMap(TargetCounts),
    inbound: std.StringHashMap(u64),

    pub fn init(allocator: std.mem.Allocator) MentionGraph {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) MentionGraph {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .edges = std.StringHashMap(TargetCounts).init(allocator),
            .inbound = std.StringHashMap(u64).init(allocator),
        };
    }

    pub fn deinit(self: *MentionGraph) void {
        var edge_it = self.edges.iterator();
        while (edge_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.edges.deinit();

        var inbound_it = self.inbound.iterator();
        while (inbound_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.inbound.deinit();

        self.* = undefined;
    }

    pub fn bump(self: *MentionGraph, from: []const u8, to: []const u8) Error!void {
        const targets = try self.ensureSource(from);
        const edge_entry = try self.ensureEdge(targets, to);
        if (edge_entry.value_ptr.* < std.math.maxInt(u32)) edge_entry.value_ptr.* += 1;

        const total_entry = try self.ensureInbound(to);
        total_entry.value_ptr.* +%= 1;
    }

    pub fn count(self: *const MentionGraph, from: []const u8, to: []const u8) u32 {
        const targets = self.edges.getPtr(from) orelse return 0;
        return targets.counts.get(to) orelse 0;
    }

    pub fn topMentioned(self: *const MentionGraph, out: []MentionTotal) usize {
        var used: usize = 0;
        var it = self.inbound.iterator();
        while (it.next()) |entry| {
            insertTop(out, &used, .{ .name = entry.key_ptr.*, .count = entry.value_ptr.* });
        }
        return used;
    }

    fn ensureSource(self: *MentionGraph, from: []const u8) Error!*TargetCounts {
        if (self.edges.getPtr(from)) |targets| return targets;
        if (self.edges.count() >= self.cfg.max_sources) return error.TooManySources;

        const owned = try self.allocator.dupe(u8, from);
        errdefer self.allocator.free(owned);
        try self.edges.putNoClobber(owned, TargetCounts.init(self.allocator));
        return self.edges.getPtr(owned).?;
    }

    fn ensureEdge(self: *MentionGraph, targets: *TargetCounts, to: []const u8) Error!std.StringHashMap(u32).Entry {
        if (targets.counts.getEntry(to)) |entry| return entry;
        if (targets.counts.count() >= self.cfg.max_targets_per_source) return error.TooManyTargets;

        const owned = try self.allocator.dupe(u8, to);
        errdefer self.allocator.free(owned);
        try targets.counts.putNoClobber(owned, 0);
        return targets.counts.getEntry(owned).?;
    }

    fn ensureInbound(self: *MentionGraph, to: []const u8) Error!std.StringHashMap(u64).Entry {
        if (self.inbound.getEntry(to)) |entry| return entry;
        if (self.inbound.count() >= self.cfg.max_mentioned) return error.TooManyMentioned;

        const owned = try self.allocator.dupe(u8, to);
        errdefer self.allocator.free(owned);
        try self.inbound.putNoClobber(owned, 0);
        return self.inbound.getEntry(owned).?;
    }

    fn insertTop(out: []MentionTotal, used: *usize, item: MentionTotal) void {
        if (out.len == 0) return;
        var pos: usize = 0;
        while (pos < used.* and better(out[pos], item)) pos += 1;
        if (pos >= out.len) return;

        if (used.* < out.len) used.* += 1;
        var i = used.* - 1;
        while (i > pos) : (i -= 1) out[i] = out[i - 1];
        out[pos] = item;
    }

    fn better(a: MentionTotal, b: MentionTotal) bool {
        if (a.count != b.count) return a.count > b.count;
        return std.mem.lessThan(u8, a.name, b.name);
    }
};

const testing = std.testing;

test "bump records directed counts" {
    var graph = MentionGraph.init(testing.allocator);
    defer graph.deinit();

    try graph.bump("alice", "bob");
    try graph.bump("alice", "bob");
    try graph.bump("bob", "alice");

    try testing.expectEqual(@as(u32, 2), graph.count("alice", "bob"));
    try testing.expectEqual(@as(u32, 1), graph.count("bob", "alice"));
    try testing.expectEqual(@as(u32, 0), graph.count("carol", "bob"));
}

test "topMentioned sorts by inbound total" {
    var graph = MentionGraph.init(testing.allocator);
    defer graph.deinit();

    try graph.bump("a", "zara");
    try graph.bump("b", "mika");
    try graph.bump("c", "mika");

    var out: [2]MentionTotal = undefined;
    const n = graph.topMentioned(&out);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("mika", out[0].name);
    try testing.expectEqual(@as(u64, 2), out[0].count);
    try testing.expectEqualStrings("zara", out[1].name);
}

test "topMentioned applies lexical tie ordering" {
    var graph = MentionGraph.init(testing.allocator);
    defer graph.deinit();

    try graph.bump("x", "bravo");
    try graph.bump("x", "alpha");

    var out: [4]MentionTotal = undefined;
    const n = graph.topMentioned(&out);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("alpha", out[0].name);
    try testing.expectEqualStrings("bravo", out[1].name);
}

test "configured bounds reject new sources and targets" {
    var graph = MentionGraph.initWithConfig(testing.allocator, .{
        .max_sources = 1,
        .max_targets_per_source = 1,
        .max_mentioned = 1,
    });
    defer graph.deinit();

    try graph.bump("a", "b");
    try testing.expectError(error.TooManyTargets, graph.bump("a", "c"));
    try testing.expectError(error.TooManySources, graph.bump("x", "b"));
}
