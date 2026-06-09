//! Clean-room renderer for the oper `ROUTE` command — inspection of the mesh
//! routing table: where nicks/channels live and the next hop to reach each
//! node. Pure and std-only; takes plain input structs and writes newline-
//! separated body lines via an `anytype` writer (std.Io.Writer style), the same
//! convention used by `stats_report.zig` / `mesh_report.zig`. The daemon wraps
//! each emitted line in its own NOTICE/numeric. No I/O, no allocation, no
//! globals.

const std = @import("std");

/// One routing-table entry: how to reach `dest` from the local node.
pub const RouteEntry = struct {
    /// Destination node/server name.
    dest: []const u8,
    /// Immediate neighbour to forward to ("" when local/direct).
    next_hop: []const u8 = "",
    /// Hop count to `dest` (0 = self).
    distance: u32 = 0,
    /// Whether `dest` is currently reachable.
    reachable: bool = true,
};

/// Where a single nick is homed in the mesh.
pub const NickLocation = struct {
    nick: []const u8,
    node: []const u8,
};

/// Which nodes host members of a channel.
pub const ChannelLocation = struct {
    channel: []const u8,
    nodes: []const []const u8 = &.{},
};

/// A snapshot of the routing table from the local node's perspective. `routes`
/// is rendered in the order given (the caller may pre-sort by distance).
pub const RouteSnapshot = struct {
    local_node: []const u8,
    routes: []const RouteEntry = &.{},
};

/// Render the full routing table: a header, one aligned row per route, and a
/// summary (route count, reachable count, max distance among reachable routes).
pub fn renderRoutes(snap: RouteSnapshot, writer: anytype) !void {
    var dest_width: usize = 4; // "dest"
    var hop_width: usize = 8; // "next-hop"
    var reachable: u32 = 0;
    var max_distance: u32 = 0;
    for (snap.routes) |r| {
        dest_width = @max(dest_width, visibleLen(r.dest));
        hop_width = @max(hop_width, if (r.next_hop.len == 0) @as(usize, 1) else visibleLen(r.next_hop));
        if (r.reachable) {
            reachable += 1;
            max_distance = @max(max_distance, r.distance);
        }
    }

    try writer.writeAll("ROUTE local=");
    try writeClean(writer, snap.local_node);
    try writer.print(" routes={d}\n", .{snap.routes.len});

    try writeCleanPadded(writer, "dest", dest_width);
    try writer.writeAll("  ");
    try writeCleanPadded(writer, "next-hop", hop_width);
    try writer.writeAll("  dist  state\n");

    for (snap.routes) |r| {
        try writeCleanPadded(writer, r.dest, dest_width);
        try writer.writeAll("  ");
        const hop = if (r.next_hop.len == 0) "-" else r.next_hop;
        try writeCleanPadded(writer, hop, hop_width);
        try writer.print("  {d:>4}  {s}\n", .{ r.distance, if (r.reachable) "up" else "unreachable" });
    }

    try writer.print("{d} routes, {d} reachable, max distance {d}\n", .{ snap.routes.len, reachable, max_distance });
}

/// Render the answer to `ROUTE <nick>`: which node homes the nick and the next
/// hop + distance to reach it. `route` is the routing entry for that node (null
/// when no route is known); pass null `loc.node` length handling via `found`.
pub fn renderNickRoute(loc: NickLocation, route: ?RouteEntry, writer: anytype) !void {
    if (loc.node.len == 0) {
        try writer.writeAll("ROUTE ");
        try writeClean(writer, loc.nick);
        try writer.writeAll(": not found\n");
        return;
    }
    try writer.writeAll("ROUTE ");
    try writeClean(writer, loc.nick);
    try writer.writeAll(" is on ");
    try writeClean(writer, loc.node);
    if (route) |r| {
        if (r.distance == 0) {
            try writer.writeAll(" (local)\n");
        } else {
            const hop = if (r.next_hop.len == 0) "-" else r.next_hop;
            try writer.writeAll(" via ");
            try writeClean(writer, hop);
            try writer.print(" ({d} hop{s}", .{ r.distance, if (r.distance == 1) "" else "s" });
            if (!r.reachable) try writer.writeAll(", unreachable");
            try writer.writeAll(")\n");
        }
    } else {
        try writer.writeAll(" (no route)\n");
    }
}

/// Render the answer to `ROUTE <channel>`: which nodes host members.
pub fn renderChannelRoute(loc: ChannelLocation, writer: anytype) !void {
    try writer.writeAll("ROUTE ");
    try writeClean(writer, loc.channel);
    if (loc.nodes.len == 0) {
        try writer.writeAll(": no members\n");
        return;
    }
    try writer.print(" spans {d} node{s}: ", .{ loc.nodes.len, if (loc.nodes.len == 1) "" else "s" });
    for (loc.nodes, 0..) |node, i| {
        if (i != 0) try writer.writeAll(", ");
        try writeClean(writer, node);
    }
    try writer.writeByte('\n');
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Visible length, treating any CR/LF as zero-width (they are never emitted).
fn visibleLen(s: []const u8) usize {
    var n: usize = 0;
    for (s) |c| {
        if (c != '\r' and c != '\n') n += 1;
    }
    return n;
}

/// Write `s` with CR/LF stripped (defence in depth — these are server-internal
/// names, but a stray newline must never break the line framing).
fn writeClean(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        if (c == '\r' or c == '\n') continue;
        try writer.writeByte(c);
    }
}

/// Write `s` (CR/LF-stripped) left-justified, padded with spaces to `width`.
fn writeCleanPadded(writer: anytype, s: []const u8, width: usize) !void {
    try writeClean(writer, s);
    var i = visibleLen(s);
    while (i < width) : (i += 1) try writer.writeByte(' ');
}

// ── tests ────────────────────────────────────────────────────────────────────

fn renderToBuf(comptime f: anytype, arg: anytype, buf: []u8) ![]const u8 {
    var w = std.Io.Writer.fixed(buf);
    try f(arg, &w);
    return w.buffered();
}

test "renderRoutes: empty table" {
    var buf: [512]u8 = undefined;
    const out = try renderToBuf(renderRoutes, RouteSnapshot{ .local_node = "node-a" }, &buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "ROUTE local=node-a routes=0") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "0 routes, 0 reachable, max distance 0") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, out, '\r') == null);
}

test "renderRoutes: multi-hop, unreachable marked, summary correct" {
    const routes = [_]RouteEntry{
        .{ .dest = "node-a", .next_hop = "", .distance = 0, .reachable = true },
        .{ .dest = "node-b", .next_hop = "node-b", .distance = 1, .reachable = true },
        .{ .dest = "node-c", .next_hop = "node-b", .distance = 3, .reachable = true },
        .{ .dest = "node-d", .next_hop = "node-b", .distance = 7, .reachable = false },
    };
    var buf: [1024]u8 = undefined;
    const out = try renderToBuf(renderRoutes, RouteSnapshot{ .local_node = "node-a", .routes = &routes }, &buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "node-c") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "unreachable") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "up") != null);
    // 4 routes, 3 reachable, max distance among reachable = 3 (the unreachable d=7 excluded).
    try std.testing.expect(std.mem.indexOf(u8, out, "4 routes, 3 reachable, max distance 3") != null);
    // direct route shows "-" next hop.
    try std.testing.expect(std.mem.indexOf(u8, out, "-") != null);
}

test "renderNickRoute: found local, found remote, not found" {
    var b2: [256]u8 = undefined;
    var w2 = std.Io.Writer.fixed(&b2);
    try renderNickRoute(.{ .nick = "alice", .node = "node-a" }, RouteEntry{ .dest = "node-a", .distance = 0 }, &w2);
    try std.testing.expect(std.mem.indexOf(u8, w2.buffered(), "alice is on node-a (local)") != null);

    var b3: [256]u8 = undefined;
    var w3 = std.Io.Writer.fixed(&b3);
    try renderNickRoute(.{ .nick = "bob", .node = "node-c" }, RouteEntry{ .dest = "node-c", .next_hop = "node-b", .distance = 2 }, &w3);
    try std.testing.expect(std.mem.indexOf(u8, w3.buffered(), "bob is on node-c via node-b (2 hops)") != null);

    var b4: [256]u8 = undefined;
    var w4 = std.Io.Writer.fixed(&b4);
    try renderNickRoute(.{ .nick = "ghost", .node = "" }, null, &w4);
    try std.testing.expect(std.mem.indexOf(u8, w4.buffered(), "ROUTE ghost: not found") != null);
}

test "renderNickRoute: singular hop wording and unreachable note" {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try renderNickRoute(.{ .nick = "carol", .node = "node-b" }, RouteEntry{ .dest = "node-b", .next_hop = "node-b", .distance = 1, .reachable = false }, &w);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "(1 hop, unreachable)") != null);
}

test "renderChannelRoute: spread across three nodes, and empty" {
    const nodes = [_][]const u8{ "node-a", "node-b", "node-c" };
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try renderChannelRoute(.{ .channel = "#ops", .nodes = &nodes }, &w);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "ROUTE #ops spans 3 nodes: node-a, node-b, node-c") != null);

    var b2: [128]u8 = undefined;
    var w2 = std.Io.Writer.fixed(&b2);
    try renderChannelRoute(.{ .channel = "#empty", .nodes = &.{} }, &w2);
    try std.testing.expect(std.mem.indexOf(u8, w2.buffered(), "ROUTE #empty: no members") != null);
}

test "CR/LF in names never breaks framing" {
    const routes = [_]RouteEntry{.{ .dest = "ev\r\nil", .next_hop = "x", .distance = 1 }};
    var buf: [512]u8 = undefined;
    const out = try renderToBuf(renderRoutes, RouteSnapshot{ .local_node = "a\nb", .routes = &routes }, &buf);
    // exactly the framing newlines: header + col header + 1 row + summary = 4.
    var nl: usize = 0;
    for (out) |c| {
        if (c == '\n') nl += 1;
        try std.testing.expect(c != '\r');
    }
    try std.testing.expectEqual(@as(usize, 4), nl);
}
