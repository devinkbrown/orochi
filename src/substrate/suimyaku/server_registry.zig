//! SUIMYAKU mesh server/node registry.
//!
//! This module tracks the bounded set of servers known to a mesh node. It is a
//! pure state container: callers supply time, allocator, and render context.
//!
//! Identity is the sovereign `NodeId` (u64) — Mizuchi's mesh has no legacy TS6
//! server-id (SID) concept; a node is known solely by its node id.
const std = @import("std");
const membership_view = @import("membership_view.zig");
const toml = @import("../../proto/toml.zig");

pub const NodeId = membership_view.NodeId;

pub const Config = struct {
    max_nodes: usize = 512,
    max_name_len: usize = 63,
    max_description_len: usize = 255,

    pub fn validate(self: Config) Error!void {
        if (self.max_nodes == 0) return error.InvalidConfig;
        if (self.max_name_len == 0) return error.InvalidConfig;
    }

    /// Overlay `[mesh.routing]` server-registry keys onto this config.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("mesh.routing.max_servers")) |v| cfg.max_nodes = @intCast(v);
        if (doc.getUint("mesh.routing.max_server_name_len")) |v| cfg.max_name_len = @intCast(v);
        if (doc.getUint("mesh.routing.max_server_desc_len")) |v| cfg.max_description_len = @intCast(v);
    }
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidConfig,
    InvalidNode,
    NameTooLong,
    DescriptionTooLong,
    RegistryFull,
    NodeExists,
    NodeNotFound,
};

pub const NodeInfo = struct {
    node_id: NodeId,
    name: []const u8,
    description: []const u8 = "",
    hopcount: u16 = 0,
    uplink: ?NodeId = null,
    last_seen_ms: i64,
};

pub const Node = struct {
    node_id: NodeId,
    name: []const u8,
    description: []const u8,
    hopcount: u16,
    uplink: ?NodeId,
    last_seen_ms: i64,
};

pub const UpsertResult = enum {
    added,
    updated,
};

pub const TopologyEntry = struct {
    node: Node,
    depth: u16,
    parent_index: ?usize,
};

pub const RenderContext = struct {
    source: []const u8,
    target: []const u8,
    links_mask: []const u8 = "*",
};

pub const RenderBuilder = struct {
    bytes: std.ArrayList(u8) = .empty,

    pub fn deinit(self: *RenderBuilder, allocator: std.mem.Allocator) void {
        self.bytes.deinit(allocator);
        self.* = .{};
    }

    pub fn clearRetainingCapacity(self: *RenderBuilder) void {
        self.bytes.clearRetainingCapacity();
    }

    pub fn items(self: *const RenderBuilder) []const u8 {
        return self.bytes.items;
    }

    pub fn appendLinks(
        self: *RenderBuilder,
        allocator: std.mem.Allocator,
        registry: *const ServerRegistry,
        ctx: RenderContext,
    ) Error!void {
        try registry.appendLinks(allocator, &self.bytes, ctx);
    }

    pub fn appendMap(
        self: *RenderBuilder,
        allocator: std.mem.Allocator,
        registry: *const ServerRegistry,
        ctx: RenderContext,
    ) Error!void {
        try registry.appendMap(allocator, &self.bytes, ctx);
    }
};

pub const ServerRegistry = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    nodes: std.ArrayList(Node) = .empty,
    by_node: std.AutoHashMap(NodeId, usize),

    pub fn init(allocator: std.mem.Allocator, cfg: Config) Error!ServerRegistry {
        try cfg.validate();

        var nodes = try std.ArrayList(Node).initCapacity(allocator, cfg.max_nodes);
        errdefer nodes.deinit(allocator);

        var by_node = std.AutoHashMap(NodeId, usize).init(allocator);
        errdefer by_node.deinit();
        try by_node.ensureTotalCapacity(@intCast(cfg.max_nodes));

        return .{
            .allocator = allocator,
            .cfg = cfg,
            .nodes = nodes,
            .by_node = by_node,
        };
    }

    pub fn deinit(self: *ServerRegistry) void {
        for (self.nodes.items) |node| self.freeNode(node);
        self.nodes.deinit(self.allocator);
        self.by_node.deinit();
        self.* = .{
            .allocator = self.allocator,
            .cfg = self.cfg,
            .by_node = std.AutoHashMap(NodeId, usize).init(self.allocator),
        };
    }

    pub fn count(self: *const ServerRegistry) usize {
        return self.nodes.items.len;
    }

    pub fn list(self: *const ServerRegistry) []const Node {
        return self.nodes.items;
    }

    pub fn get(self: *const ServerRegistry, node_id: NodeId) ?*const Node {
        const idx = self.by_node.get(node_id) orelse return null;
        return &self.nodes.items[idx];
    }

    pub fn contains(self: *const ServerRegistry, node_id: NodeId) bool {
        return self.by_node.contains(node_id);
    }

    pub fn add(self: *ServerRegistry, info: NodeInfo) Error!void {
        try self.validateInfo(info);
        if (self.contains(info.node_id)) return error.NodeExists;
        try self.insertNew(info);
    }

    pub fn update(self: *ServerRegistry, info: NodeInfo) Error!void {
        try self.validateInfo(info);
        const idx = self.by_node.get(info.node_id) orelse return error.NodeNotFound;
        try self.replaceAt(idx, info);
    }

    pub fn addOrUpdate(self: *ServerRegistry, info: NodeInfo) Error!UpsertResult {
        try self.validateInfo(info);
        if (self.by_node.get(info.node_id)) |idx| {
            try self.replaceAt(idx, info);
            return .updated;
        }
        try self.insertNew(info);
        return .added;
    }

    pub fn markSeen(self: *ServerRegistry, node_id: NodeId, last_seen_ms: i64) Error!bool {
        if (!validNode(node_id)) return error.InvalidNode;
        const idx = self.by_node.get(node_id) orelse return false;
        self.nodes.items[idx].last_seen_ms = last_seen_ms;
        return true;
    }

    pub fn remove(self: *ServerRegistry, node_id: NodeId) Error!bool {
        if (!validNode(node_id)) return error.InvalidNode;
        const idx = self.by_node.get(node_id) orelse return false;
        const old = self.nodes.orderedRemove(idx);
        self.freeNode(old);

        for (self.nodes.items) |*node| {
            if (node.uplink == node_id) {
                node.uplink = null;
                node.hopcount = 0;
            }
        }
        self.rebuildIndex();
        return true;
    }

    pub fn buildTopology(
        self: *const ServerRegistry,
        allocator: std.mem.Allocator,
        out: *std.ArrayList(TopologyEntry),
    ) Error!void {
        out.clearRetainingCapacity();
        try out.ensureTotalCapacity(allocator, self.nodes.items.len);

        const visited = try allocator.alloc(bool, self.nodes.items.len);
        defer allocator.free(visited);
        @memset(visited, false);

        for (self.nodes.items, 0..) |node, idx| {
            if (node.uplink == null or self.by_node.get(node.uplink.?) == null) {
                try self.appendTopologyFrom(idx, null, 0, visited, out);
            }
        }
        for (self.nodes.items, 0..) |_, idx| {
            if (!visited[idx]) try self.appendTopologyFrom(idx, null, 0, visited, out);
        }
    }

    pub fn appendLinks(
        self: *const ServerRegistry,
        allocator: std.mem.Allocator,
        out: *std.ArrayList(u8),
        ctx: RenderContext,
    ) Error!void {
        for (self.nodes.items) |node| {
            const uplink_name = if (node.uplink) |uplink_id|
                if (self.get(uplink_id)) |uplink| uplink.name else "*"
            else
                "*";
            try out.print(
                allocator,
                ":{s} 364 {s} {s} {s} :{d} {s}\r\n",
                .{ ctx.source, ctx.target, ctx.links_mask, node.name, node.hopcount, uplink_name },
            );
        }
        try out.print(
            allocator,
            ":{s} 365 {s} {s} :End of LINKS list\r\n",
            .{ ctx.source, ctx.target, ctx.links_mask },
        );
    }

    pub fn appendMap(
        self: *const ServerRegistry,
        allocator: std.mem.Allocator,
        out: *std.ArrayList(u8),
        ctx: RenderContext,
    ) Error!void {
        var topo: std.ArrayList(TopologyEntry) = .empty;
        defer topo.deinit(allocator);
        try self.buildTopology(allocator, &topo);

        for (topo.items) |entry| {
            try out.print(allocator, ":{s} 015 {s} :", .{ ctx.source, ctx.target });
            try appendIndent(allocator, out, entry.depth);
            try out.print(
                allocator,
                "{s} [{d}] {s}\r\n",
                .{ entry.node.name, entry.node.node_id, entry.node.description },
            );
        }
        try out.print(allocator, ":{s} 017 {s} :End of /MAP\r\n", .{ ctx.source, ctx.target });
    }

    fn validateInfo(self: *const ServerRegistry, info: NodeInfo) Error!void {
        if (!validNode(info.node_id)) return error.InvalidNode;
        if (info.uplink) |uplink| {
            if (!validNode(uplink) or uplink == info.node_id) return error.InvalidNode;
        }
        if (info.name.len == 0 or info.name.len > self.cfg.max_name_len) return error.NameTooLong;
        if (info.description.len > self.cfg.max_description_len) return error.DescriptionTooLong;
        if (!validLineAtom(info.name) or !validLineText(info.description)) return error.InvalidNode;
    }

    fn insertNew(self: *ServerRegistry, info: NodeInfo) Error!void {
        if (self.nodes.items.len >= self.cfg.max_nodes) return error.RegistryFull;
        const owned = try self.ownedNode(info);
        errdefer self.freeNode(owned);
        self.nodes.appendAssumeCapacity(owned);
        self.by_node.putAssumeCapacityNoClobber(info.node_id, self.nodes.items.len - 1);
    }

    fn replaceAt(self: *ServerRegistry, idx: usize, info: NodeInfo) Error!void {
        const owned = try self.ownedNode(info);
        const old = self.nodes.items[idx];
        self.nodes.items[idx] = owned;
        self.freeNode(old);
    }

    fn ownedNode(self: *ServerRegistry, info: NodeInfo) Error!Node {
        const name = try self.allocator.dupe(u8, info.name);
        errdefer self.allocator.free(name);
        const description = try self.allocator.dupe(u8, info.description);
        errdefer self.allocator.free(description);
        return .{
            .node_id = info.node_id,
            .name = name,
            .description = description,
            .hopcount = info.hopcount,
            .uplink = info.uplink,
            .last_seen_ms = info.last_seen_ms,
        };
    }

    fn freeNode(self: *ServerRegistry, node: Node) void {
        self.allocator.free(node.name);
        self.allocator.free(node.description);
    }

    fn rebuildIndex(self: *ServerRegistry) void {
        self.by_node.clearRetainingCapacity();
        for (self.nodes.items, 0..) |node, idx| {
            self.by_node.putAssumeCapacityNoClobber(node.node_id, idx);
        }
    }

    fn appendTopologyFrom(
        self: *const ServerRegistry,
        idx: usize,
        parent_index: ?usize,
        depth: u16,
        visited: []bool,
        out: *std.ArrayList(TopologyEntry),
    ) Error!void {
        if (visited[idx]) return;
        visited[idx] = true;

        const out_parent = parent_index orelse findTopologyParent(out.items, self.nodes.items[idx].uplink);
        const out_idx = out.items.len;
        out.appendAssumeCapacity(.{
            .node = self.nodes.items[idx],
            .depth = depth,
            .parent_index = out_parent,
        });

        for (self.nodes.items, 0..) |node, child_idx| {
            if (node.uplink == self.nodes.items[idx].node_id) {
                try self.appendTopologyFrom(child_idx, out_idx, depth + 1, visited, out);
            }
        }
    }
};

fn validNode(node_id: NodeId) bool {
    return node_id != 0;
}

fn validLineAtom(text: []const u8) bool {
    for (text) |ch| {
        if (ch <= ' ' or ch == ':' or ch == 0x7f) return false;
    }
    return true;
}

fn validLineText(text: []const u8) bool {
    for (text) |ch| {
        if (ch == '\r' or ch == '\n' or ch == 0) return false;
    }
    return true;
}

fn appendIndent(allocator: std.mem.Allocator, out: *std.ArrayList(u8), depth: u16) Error!void {
    var i: u16 = 0;
    while (i < depth) : (i += 1) try out.appendSlice(allocator, "  ");
}

fn findTopologyParent(entries: []const TopologyEntry, uplink: ?NodeId) ?usize {
    const parent_id = uplink orelse return null;
    for (entries, 0..) |entry, idx| {
        if (entry.node.node_id == parent_id) return idx;
    }
    return null;
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, haystack, needle) != null);
}

test "add update and list known nodes" {
    var registry = try ServerRegistry.init(std.testing.allocator, .{ .max_nodes = 4 });
    defer registry.deinit();

    try registry.add(.{
        .node_id = 1,
        .name = "irc.example.test",
        .description = "root",
        .last_seen_ms = 100,
    });
    try registry.add(.{
        .node_id = 2,
        .name = "leaf.example.test",
        .description = "leaf",
        .hopcount = 1,
        .uplink = 1,
        .last_seen_ms = 110,
    });
    try registry.update(.{
        .node_id = 2,
        .name = "leaf.example.test",
        .description = "updated leaf",
        .hopcount = 1,
        .uplink = 1,
        .last_seen_ms = 120,
    });

    try std.testing.expectEqual(@as(usize, 2), registry.count());
    try std.testing.expectEqualStrings("updated leaf", registry.get(2).?.description);
    try std.testing.expectEqual(@as(i64, 120), registry.list()[1].last_seen_ms);
}

test "render LINKS and MAP numeric lines" {
    var registry = try ServerRegistry.init(std.testing.allocator, .{ .max_nodes = 5 });
    defer registry.deinit();

    _ = try registry.addOrUpdate(.{
        .node_id = 10,
        .name = "alpha.net",
        .description = "Alpha Hub",
        .last_seen_ms = 100,
    });
    _ = try registry.addOrUpdate(.{
        .node_id = 11,
        .name = "beta.net",
        .description = "Beta Leaf",
        .hopcount = 1,
        .uplink = 10,
        .last_seen_ms = 101,
    });
    _ = try registry.addOrUpdate(.{
        .node_id = 12,
        .name = "gamma.net",
        .description = "Gamma Leaf",
        .hopcount = 2,
        .uplink = 11,
        .last_seen_ms = 102,
    });

    var builder: RenderBuilder = .{};
    defer builder.deinit(std.testing.allocator);
    const ctx: RenderContext = .{ .source = "alpha.net", .target = "nick" };

    try builder.appendLinks(std.testing.allocator, &registry, ctx);
    try expectContains(builder.items(), ":alpha.net 364 nick * beta.net :1 alpha.net\r\n");
    try expectContains(builder.items(), ":alpha.net 365 nick * :End of LINKS list\r\n");

    builder.clearRetainingCapacity();
    try builder.appendMap(std.testing.allocator, &registry, ctx);
    try expectContains(builder.items(), ":alpha.net 015 nick :alpha.net [10] Alpha Hub\r\n");
    try expectContains(builder.items(), ":alpha.net 015 nick :  beta.net [11] Beta Leaf\r\n");
    try expectContains(builder.items(), ":alpha.net 015 nick :    gamma.net [12] Gamma Leaf\r\n");
    try expectContains(builder.items(), ":alpha.net 017 nick :End of /MAP\r\n");
}

test "remove on split detaches children without leaks" {
    var registry = try ServerRegistry.init(std.testing.allocator, .{ .max_nodes = 4 });
    defer registry.deinit();

    try registry.add(.{ .node_id = 1, .name = "root.net", .description = "Root", .last_seen_ms = 1 });
    try registry.add(.{ .node_id = 2, .name = "split.net", .description = "Split", .hopcount = 1, .uplink = 1, .last_seen_ms = 2 });
    try registry.add(.{ .node_id = 3, .name = "child.net", .description = "Child", .hopcount = 2, .uplink = 2, .last_seen_ms = 3 });

    try std.testing.expect(try registry.remove(2));
    try std.testing.expect(!registry.contains(2));
    try std.testing.expectEqual(@as(?NodeId, null), registry.get(3).?.uplink);
    try std.testing.expectEqual(@as(u16, 0), registry.get(3).?.hopcount);
    try std.testing.expectEqual(@as(usize, 2), registry.count());
}

test "topology view gives parent indexes" {
    var registry = try ServerRegistry.init(std.testing.allocator, .{ .max_nodes = 4 });
    defer registry.deinit();

    try registry.add(.{ .node_id = 1, .name = "root.net", .last_seen_ms = 1 });
    try registry.add(.{ .node_id = 2, .name = "leaf-a.net", .hopcount = 1, .uplink = 1, .last_seen_ms = 2 });
    try registry.add(.{ .node_id = 3, .name = "leaf-b.net", .hopcount = 1, .uplink = 1, .last_seen_ms = 3 });

    var topo: std.ArrayList(TopologyEntry) = .empty;
    defer topo.deinit(std.testing.allocator);
    try registry.buildTopology(std.testing.allocator, &topo);

    try std.testing.expectEqual(@as(usize, 3), topo.items.len);
    try std.testing.expectEqual(@as(NodeId, 1), topo.items[0].node.node_id);
    try std.testing.expectEqual(@as(?usize, null), topo.items[0].parent_index);
    try std.testing.expectEqual(@as(?usize, 0), topo.items[1].parent_index);
    try std.testing.expectEqual(@as(?usize, 0), topo.items[2].parent_index);
}

test "bounds and validation reject bad input" {
    try std.testing.expectError(error.InvalidConfig, ServerRegistry.init(std.testing.allocator, .{ .max_nodes = 0 }));

    var registry = try ServerRegistry.init(std.testing.allocator, .{
        .max_nodes = 1,
        .max_name_len = 8,
        .max_description_len = 8,
    });
    defer registry.deinit();

    try std.testing.expectError(error.InvalidNode, registry.add(.{ .node_id = 0, .name = "bad", .last_seen_ms = 1 }));
    try std.testing.expectError(error.NameTooLong, registry.add(.{ .node_id = 1, .name = "too-long-name", .last_seen_ms = 1 }));
    try std.testing.expectError(error.DescriptionTooLong, registry.add(.{ .node_id = 1, .name = "ok.net", .description = "too long desc", .last_seen_ms = 1 }));

    try registry.add(.{ .node_id = 1, .name = "ok.net", .description = "ok", .last_seen_ms = 1 });
    try std.testing.expectError(error.RegistryFull, registry.add(.{ .node_id = 2, .name = "no.net", .last_seen_ms = 2 }));
}

test "Config.applyToml overlays mesh.routing server-registry keys" {
    const allocator = std.testing.allocator;
    var doc = try toml.parse(allocator,
        \\[mesh.routing]
        \\max_servers = 1024
        \\max_server_desc_len = 512
    );
    defer doc.deinit(allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(usize, 1024), cfg.max_nodes);
    try std.testing.expectEqual(@as(usize, 512), cfg.max_description_len);
    try std.testing.expectEqual(@as(usize, 63), cfg.max_name_len); // default
}
