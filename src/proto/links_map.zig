// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Suimyaku mesh-native LINKS and MAP numeric builders.
//!
//! These replies keep the familiar IRC numeric surface while reporting the
//! current CRDT mesh snapshot. `hops` is distance from the local node, and
//! `peers` is the node's visible mesh degree; no spanning-tree parent or TS6
//! route is invented by this module.
const std = @import("std");
const numeric = @import("numeric.zig");

pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_REQUESTER_BYTES: usize = 64;
pub const DEFAULT_MAX_NODE_BYTES: usize = 255;
pub const DEFAULT_MAX_INFO_BYTES: usize = 256;
/// Hop ceiling: bounds MAP indentation so attacker-influenced mesh data cannot
/// amplify a u16 hop count into a multi-KB indent (DoS).
pub const DEFAULT_MAX_HOPS: u16 = 64;
/// Hard IRC line ceiling (excl. CRLF) so a single LINKS/MAP line can never
/// exceed the protocol limit regardless of caller scratch size.
pub const DEFAULT_MAX_LINE_BYTES: usize = 512;

pub const LinksMapError = error{
    InvalidServerName,
    ServerNameTooLong,
    InvalidRequester,
    RequesterTooLong,
    InvalidNodeName,
    NodeNameTooLong,
    InvalidInfo,
    InfoTooLong,
    TooManyHops,
    LineTooLong,
    OutputTooSmall,
};

/// Compile-time limits for mesh reply builders and validators.
pub const Params = struct {
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_requester_bytes: usize = DEFAULT_MAX_REQUESTER_BYTES,
    max_node_bytes: usize = DEFAULT_MAX_NODE_BYTES,
    max_info_bytes: usize = DEFAULT_MAX_INFO_BYTES,
    max_hops: u16 = DEFAULT_MAX_HOPS,
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
};

/// One Suimyaku mesh node visible to LINKS/MAP.
pub const MeshNode = struct {
    name: []const u8,
    hops: u16,
    peers: u16,
    info: []const u8 = "",
};

/// Reply-level data shared by LINKS and MAP numerics.
pub const ReplyContext = struct {
    server_name: []const u8,
    requester: []const u8,
};

/// Build one mesh-native RPL_LINKS (364) line.
pub fn writeLinksNode(out: []u8, ctx: ReplyContext, node: MeshNode) LinksMapError![]const u8 {
    return writeLinksNodeWith(.{}, out, ctx, node);
}

/// Build one RPL_LINKS line using caller-selected validation limits.
pub fn writeLinksNodeWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    node: MeshNode,
) LinksMapError![]const u8 {
    try validateContextWith(params, ctx);
    try validateNodeWith(params, node);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(.RPL_LINKS, ctx.server_name, ctx.requester);
    try b.spaceBytes(node.name);
    try b.spaceBytes("suimyaku");
    try b.appendBytes(" :");
    try b.appendUnsigned(node.hops);
    try b.appendBytes(" hops ");
    try b.appendUnsigned(node.peers);
    try b.appendBytes(" peers");
    if (node.info.len != 0) {
        try b.appendByte(' ');
        try b.appendBytes(node.info);
    }
    try b.crlf();
    return b.slice();
}

/// Build RPL_ENDOFLINKS (365) for a completed mesh LINKS reply.
pub fn writeLinksEnd(out: []u8, ctx: ReplyContext) LinksMapError![]const u8 {
    return writeLinksEndWith(.{}, out, ctx);
}

/// Build RPL_ENDOFLINKS using caller-selected validation limits.
pub fn writeLinksEndWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
) LinksMapError![]const u8 {
    try validateContextWith(params, ctx);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(.RPL_ENDOFLINKS, ctx.server_name, ctx.requester);
    try b.spaceBytes("*");
    try b.spaceTrailing("End of Suimyaku LINKS");
    try b.crlf();
    return b.slice();
}

/// Emit RPL_LINKS lines followed by RPL_ENDOFLINKS to `sink.send(line)`.
pub fn emitLinks(
    nodes: []const MeshNode,
    ctx: ReplyContext,
    scratch: []u8,
    sink: anytype,
) LinksMapError!void {
    return emitLinksWith(.{}, nodes, ctx, scratch, sink);
}

/// Emit LINKS using caller-selected validation limits.
pub fn emitLinksWith(
    comptime params: Params,
    nodes: []const MeshNode,
    ctx: ReplyContext,
    scratch: []u8,
    sink: anytype,
) LinksMapError!void {
    try validateContextWith(params, ctx);
    try validateNodesWith(params, nodes);

    for (nodes) |node| {
        try sink.send(try writeLinksNodeWith(params, scratch, ctx, node));
    }
    try sink.send(try writeLinksEndWith(params, scratch, ctx));
}

/// Build one RPL_MAP (15) or RPL_MAPMORE (16) line.
///
/// Pass `first_line = true` for the first visible node; subsequent nodes use
/// RPL_MAPMORE. Indentation is two spaces per hop, preserving caller order
/// while making mesh distance visible.
pub fn writeMapNode(
    out: []u8,
    ctx: ReplyContext,
    node: MeshNode,
    first_line: bool,
) LinksMapError![]const u8 {
    return writeMapNodeWith(.{}, out, ctx, node, first_line);
}

/// Build one MAP line using caller-selected validation limits.
pub fn writeMapNodeWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    node: MeshNode,
    first_line: bool,
) LinksMapError![]const u8 {
    try validateContextWith(params, ctx);
    try validateNodeWith(params, node);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(if (first_line) .RPL_MAP else .RPL_MAPMORE, ctx.server_name, ctx.requester);
    try b.appendBytes(" :");

    var remaining_indent = node.hops;
    while (remaining_indent != 0) : (remaining_indent -= 1) {
        try b.appendBytes("  ");
    }

    try b.appendBytes(node.name);
    try b.appendBytes(" (hops=");
    try b.appendUnsigned(node.hops);
    try b.appendBytes(" peers=");
    try b.appendUnsigned(node.peers);
    try b.appendByte(')');
    if (node.info.len != 0) {
        try b.appendByte(' ');
        try b.appendBytes(node.info);
    }
    try b.crlf();
    return b.slice();
}

/// Build RPL_MAPEND (17) for a completed mesh MAP reply.
pub fn writeMapEnd(out: []u8, ctx: ReplyContext) LinksMapError![]const u8 {
    return writeMapEndWith(.{}, out, ctx);
}

/// Build RPL_MAPEND using caller-selected validation limits.
pub fn writeMapEndWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
) LinksMapError![]const u8 {
    try validateContextWith(params, ctx);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(.RPL_MAPEND, ctx.server_name, ctx.requester);
    try b.spaceTrailing("End of Suimyaku MAP");
    try b.crlf();
    return b.slice();
}

/// Emit an indented MAP view followed by RPL_MAPEND to `sink.send(line)`.
pub fn emitMap(
    nodes: []const MeshNode,
    ctx: ReplyContext,
    scratch: []u8,
    sink: anytype,
) LinksMapError!void {
    return emitMapWith(.{}, nodes, ctx, scratch, sink);
}

/// Emit MAP using caller-selected validation limits.
pub fn emitMapWith(
    comptime params: Params,
    nodes: []const MeshNode,
    ctx: ReplyContext,
    scratch: []u8,
    sink: anytype,
) LinksMapError!void {
    try validateContextWith(params, ctx);
    try validateNodesWith(params, nodes);

    for (nodes, 0..) |node, index| {
        try sink.send(try writeMapNodeWith(params, scratch, ctx, node, index == 0));
    }
    try sink.send(try writeMapEndWith(params, scratch, ctx));
}

pub fn validateNode(node: MeshNode) LinksMapError!void {
    return validateNodeWith(.{}, node);
}

pub fn validateNodeWith(comptime params: Params, node: MeshNode) LinksMapError!void {
    try validateNodeNameWith(params, node.name);
    try validateInfoWith(params, node.info);
    if (node.hops > params.max_hops) return error.TooManyHops;
}

pub fn validateNodeName(name: []const u8) LinksMapError!void {
    return validateNodeNameWith(.{}, name);
}

pub fn validateNodeNameWith(comptime params: Params, name: []const u8) LinksMapError!void {
    if (name.len == 0) return error.InvalidNodeName;
    if (name.len > params.max_node_bytes) return error.NodeNameTooLong;
    for (name) |ch| {
        if (!validNodeNameByte(ch)) return error.InvalidNodeName;
    }
}

pub fn validateInfo(info: []const u8) LinksMapError!void {
    return validateInfoWith(.{}, info);
}

pub fn validateInfoWith(comptime params: Params, info: []const u8) LinksMapError!void {
    if (info.len > params.max_info_bytes) return error.InfoTooLong;
    for (info) |ch| {
        if (!validInfoByte(ch)) return error.InvalidInfo;
    }
}

fn validateContextWith(comptime params: Params, ctx: ReplyContext) LinksMapError!void {
    try validateServerNameWith(params, ctx.server_name);
    try validateRequesterWith(params, ctx.requester);
}

fn validateNodesWith(comptime params: Params, nodes: []const MeshNode) LinksMapError!void {
    for (nodes) |node| {
        try validateNodeWith(params, node);
    }
}

fn validateServerNameWith(comptime params: Params, server_name: []const u8) LinksMapError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_bytes) return error.ServerNameTooLong;
    for (server_name) |ch| {
        if (!validNodeNameByte(ch)) return error.InvalidServerName;
    }
}

fn validateRequesterWith(comptime params: Params, requester: []const u8) LinksMapError!void {
    if (requester.len == 0) return error.InvalidRequester;
    if (requester.len > params.max_requester_bytes) return error.RequesterTooLong;
    for (requester) |ch| {
        if (!validParamByte(ch)) return error.InvalidRequester;
    }
}

fn validNodeNameByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', ':', '[', ']', '/' => true,
        else => false,
    };
}

fn validParamByte(ch: u8) bool {
    return switch (ch) {
        0, ' ', '\t', '\r', '\n' => false,
        else => ch >= 0x21 and ch != 0x7f,
    };
}

fn validInfoByte(ch: u8) bool {
    return ch >= 0x20 and ch != 0x7f;
}

const LineBuilder = struct {
    out: []u8,
    len: usize = 0,
    max: usize,

    fn init(out: []u8, max_line_bytes: usize) LineBuilder {
        return .{ .out = out, .max = @min(out.len, max_line_bytes) };
    }

    fn slice(self: *const LineBuilder) []const u8 {
        return self.out[0..self.len];
    }

    fn numericPrefix(
        self: *LineBuilder,
        code: numeric.Numeric,
        server_name: []const u8,
        requester: []const u8,
    ) LinksMapError!void {
        try self.appendByte(':');
        try self.appendBytes(server_name);
        try self.appendByte(' ');

        var code_buf: [3]u8 = undefined;
        try self.appendBytes(numeric.formatCode(code, &code_buf));
        try self.appendByte(' ');
        try self.appendBytes(requester);
    }

    fn spaceBytes(self: *LineBuilder, bytes: []const u8) LinksMapError!void {
        try self.appendByte(' ');
        try self.appendBytes(bytes);
    }

    fn spaceTrailing(self: *LineBuilder, bytes: []const u8) LinksMapError!void {
        try self.appendBytes(" :");
        try self.appendBytes(bytes);
    }

    fn appendUnsigned(self: *LineBuilder, value: u16) LinksMapError!void {
        var buf: [5]u8 = undefined;
        var n: usize = buf.len;
        var current = value;

        while (true) {
            n -= 1;
            buf[n] = @as(u8, '0') + @as(u8, @intCast(current % 10));
            current /= 10;
            if (current == 0) break;
        }

        try self.appendBytes(buf[n..]);
    }

    fn crlf(self: *LineBuilder) LinksMapError!void {
        try self.appendBytes("\r\n");
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) LinksMapError!void {
        if (self.out.len - self.len < bytes.len) return error.OutputTooSmall;
        if (self.max - self.len < bytes.len) return error.LineTooLong;
        @memcpy(self.out[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) LinksMapError!void {
        if (self.out.len - self.len < 1) return error.OutputTooSmall;
        if (self.max - self.len < 1) return error.LineTooLong;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

const TestSink = struct {
    lines: [][]const u8,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,

    fn send(self: *TestSink, line: []const u8) LinksMapError!void {
        if (self.count >= self.lines.len) return error.OutputTooSmall;
        if (self.storage.len - self.used < line.len) return error.OutputTooSmall;
        const start = self.used;
        const end = start + line.len;
        @memcpy(self.storage[start..end], line);
        self.lines[self.count] = self.storage[start..end];
        self.count += 1;
        self.used = end;
    }

    fn slice(self: *const TestSink) []const []const u8 {
        return self.lines[0..self.count];
    }
};

fn sampleContext() ReplyContext {
    return .{
        .server_name = "irc.local",
        .requester = "alice",
    };
}

test "single-node mesh emits just us for LINKS and MAP" {
    const nodes = [_]MeshNode{
        .{ .name = "irc.local", .hops = 0, .peers = 0, .info = "local mesh node" },
    };

    var scratch: [160]u8 = undefined;
    var links_slots: [4][]const u8 = undefined;
    var links_storage: [512]u8 = undefined;
    var sink = TestSink{ .lines = &links_slots, .storage = &links_storage };
    try emitLinks(&nodes, sampleContext(), &scratch, &sink);

    var map_slots: [4][]const u8 = undefined;
    var map_storage: [512]u8 = undefined;
    var map_sink = TestSink{ .lines = &map_slots, .storage = &map_storage };
    try emitMap(&nodes, sampleContext(), &scratch, &map_sink);

    try std.testing.expectEqual(@as(usize, 2), sink.slice().len);
    try std.testing.expectEqualStrings(
        ":irc.local 364 alice irc.local suimyaku :0 hops 0 peers local mesh node\r\n",
        sink.slice()[0],
    );
    try std.testing.expectEqualStrings(
        ":irc.local 365 alice * :End of Suimyaku LINKS\r\n",
        sink.slice()[1],
    );

    try std.testing.expectEqual(@as(usize, 2), map_sink.slice().len);
    try std.testing.expectEqualStrings(
        ":irc.local 015 alice :irc.local (hops=0 peers=0) local mesh node\r\n",
        map_sink.slice()[0],
    );
    try std.testing.expectEqualStrings(
        ":irc.local 017 alice :End of Suimyaku MAP\r\n",
        map_sink.slice()[1],
    );
}

test "multi-node mesh renders peer metadata and hop indentation" {
    const nodes = [_]MeshNode{
        .{ .name = "irc.local", .hops = 0, .peers = 2, .info = "mesh root" },
        .{ .name = "edge-a", .hops = 1, .peers = 3, .info = "regional edge" },
        .{ .name = "leaf-b", .hops = 2, .peers = 1, .info = "leaf" },
    };

    var scratch: [192]u8 = undefined;
    var links_slots: [5][]const u8 = undefined;
    var links_storage: [768]u8 = undefined;
    var links_sink = TestSink{ .lines = &links_slots, .storage = &links_storage };
    try emitLinks(&nodes, sampleContext(), &scratch, &links_sink);

    try std.testing.expectEqual(@as(usize, 4), links_sink.slice().len);
    try std.testing.expectEqualStrings(
        ":irc.local 364 alice edge-a suimyaku :1 hops 3 peers regional edge\r\n",
        links_sink.slice()[1],
    );

    var map_slots: [5][]const u8 = undefined;
    var map_storage: [768]u8 = undefined;
    var map_sink = TestSink{ .lines = &map_slots, .storage = &map_storage };
    try emitMap(&nodes, sampleContext(), &scratch, &map_sink);

    try std.testing.expectEqual(@as(usize, 4), map_sink.slice().len);
    try std.testing.expectEqualStrings(
        ":irc.local 015 alice :irc.local (hops=0 peers=2) mesh root\r\n",
        map_sink.slice()[0],
    );
    try std.testing.expectEqualStrings(
        ":irc.local 016 alice :  edge-a (hops=1 peers=3) regional edge\r\n",
        map_sink.slice()[1],
    );
    try std.testing.expectEqualStrings(
        ":irc.local 016 alice :    leaf-b (hops=2 peers=1) leaf\r\n",
        map_sink.slice()[2],
    );
}

test "buffer too small is reported without truncation" {
    var out: [24]u8 = undefined;
    const node = MeshNode{ .name = "irc.local", .hops = 0, .peers = 0, .info = "local mesh node" };

    try std.testing.expectError(
        error.OutputTooSmall,
        writeLinksNode(&out, sampleContext(), node),
    );
    try std.testing.expectError(
        error.OutputTooSmall,
        writeMapNode(&out, sampleContext(), node, true),
    );
}

test "malformed mesh node is rejected before sink emission" {
    const nodes = [_]MeshNode{
        .{ .name = "irc.local", .hops = 0, .peers = 1, .info = "ok" },
        .{ .name = "bad node", .hops = 1, .peers = 1, .info = "space in name" },
    };

    var scratch: [160]u8 = undefined;
    var line_slots: [4][]const u8 = undefined;
    var storage: [512]u8 = undefined;
    var sink = TestSink{ .lines = &line_slots, .storage = &storage };

    try std.testing.expectError(
        error.InvalidNodeName,
        emitLinks(&nodes, sampleContext(), &scratch, &sink),
    );
    try std.testing.expectEqual(@as(usize, 0), sink.slice().len);

    try std.testing.expectError(error.InvalidNodeName, validateNodeName("bad node"));
    try std.testing.expectError(error.InvalidNodeName, validateNodeName("bad\rnode"));
    try std.testing.expectError(error.InvalidInfo, validateInfo("bad\rinfo"));
}

test "excessive hops are rejected (indent amplification guard)" {
    var buf: [4096]u8 = undefined;
    const ctx = ReplyContext{ .server_name = "orochi.local", .requester = "alice" };
    // u16-max hops would otherwise render a ~128KB indent.
    try std.testing.expectError(error.TooManyHops, writeMapNode(&buf, ctx, .{ .name = "n", .hops = 65535, .peers = 1 }, true));
    // At/under the ceiling is accepted.
    _ = try writeMapNode(&buf, ctx, .{ .name = "n", .hops = DEFAULT_MAX_HOPS, .peers = 1 }, true);
}

test "a single line cannot exceed the protocol limit even with a large scratch" {
    var buf: [4096]u8 = undefined;
    const ctx = ReplyContext{ .server_name = "orochi.local", .requester = "alice" };
    // 256-byte info + indent pushes the line past 512 -> LineTooLong, not a giant line.
    const info = @as([256]u8, @splat('x'));
    try std.testing.expectError(error.LineTooLong, writeMapNodeWith(.{}, &buf, ctx, .{ .name = &(@as([200]u8, @splat('n'))), .hops = DEFAULT_MAX_HOPS, .peers = 1, .info = &info }, true));
}
