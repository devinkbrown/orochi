// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure renderer for the oper MESH/NETSTAT body.
//!
//! This module owns no daemon state and performs no I/O. Callers pass a plain
//! `MeshSnapshot` and a `std.Io.Writer`-style sink; the renderer emits
//! newline-separated NOTICE-body lines.

const std = @import("std");

pub const PeerState = enum { connecting, handshaking, established, draining, down };

pub const PeerLink = struct {
    /// Remote server name.
    name: []const u8,
    /// ip:port or host.
    addr: []const u8 = "",
    state: PeerState,
    /// Smoothed round-trip time.
    rtt_ms: u32 = 0,
    bytes_in: u64 = 0,
    bytes_out: u64 = 0,
    /// Link established/attempt time as Unix-epoch seconds.
    since_unix: i64 = 0,
    /// Distance in hops; 1 means direct.
    hops: u8 = 1,
};

pub const MeshSnapshot = struct {
    local_node: []const u8,
    peers: []const PeerLink,
    reachable_nodes: u32 = 0,
    partitioned_nodes: u32 = 0,
    /// Concord root hash, usually a short hex prefix.
    root_hash_hex: []const u8 = "",
};

pub fn peerStateWord(s: PeerState) []const u8 {
    return switch (s) {
        .connecting => "connecting",
        .handshaking => "handshaking",
        .established => "established",
        .draining => "draining",
        .down => "down",
    };
}

pub fn formatBytes(buf: []u8, n: u64) []const u8 {
    if (n < 1024) {
        var w = std.Io.Writer.fixed(buf);
        w.print("{d} B", .{n}) catch return buf[0..0];
        return w.buffered();
    }

    const unit, const suffix = if (n >= (1 << 30))
        .{ @as(u64, 1 << 30), "GB" }
    else if (n >= (1 << 20))
        .{ @as(u64, 1 << 20), "MB" }
    else
        .{ @as(u64, 1 << 10), "KB" };

    const tenths: u128 = (@as(u128, n) * 10 + unit / 2) / unit;
    var w = std.Io.Writer.fixed(buf);
    w.print("{d}.{d} {s}", .{ tenths / 10, tenths % 10, suffix }) catch return buf[0..0];
    return w.buffered();
}

pub fn renderMesh(snap: MeshSnapshot, writer: anytype) !void {
    var name_width: usize = 4;
    var addr_width: usize = 4;
    var established: u32 = 0;

    for (snap.peers) |peer| {
        name_width = @max(name_width, visibleLen(peer.name));
        addr_width = @max(addr_width, visibleLen(peer.addr));
        if (peer.state == .established) established += 1;
    }

    try writer.writeAll("MESH local=");
    try writeClean(writer, snap.local_node);
    try writer.print(" reachable={d} partitioned={d} root=", .{ snap.reachable_nodes, snap.partitioned_nodes });
    if (snap.root_hash_hex.len == 0) {
        try writer.writeByte('-');
    } else {
        try writeClean(writer, snap.root_hash_hex);
    }
    try writer.writeByte('\n');

    try writeCleanPadded(writer, "peer", name_width);
    try writer.writeAll("  ");
    try writeCleanPadded(writer, "addr", addr_width);
    try writer.writeAll("  state          rtt  hp        in       out  since\n");

    for (snap.peers) |peer| {
        var rtt_buf: [24]u8 = undefined;
        var hops_buf: [8]u8 = undefined;
        var in_buf: [40]u8 = undefined;
        var out_buf: [40]u8 = undefined;
        var since_buf: [32]u8 = undefined;

        var rtt_writer = std.Io.Writer.fixed(&rtt_buf);
        rtt_writer.print("{d}ms", .{peer.rtt_ms}) catch unreachable;

        var hops_writer = std.Io.Writer.fixed(&hops_buf);
        hops_writer.print("{d}", .{peer.hops}) catch unreachable;

        const in_text = formatBytes(&in_buf, peer.bytes_in);
        const out_text = formatBytes(&out_buf, peer.bytes_out);
        const since_text = formatSince(&since_buf, peer.since_unix);

        try writeCleanPadded(writer, peer.name, name_width);
        try writer.writeAll("  ");
        if (peer.addr.len == 0) {
            try writeCleanPadded(writer, "-", addr_width);
        } else {
            try writeCleanPadded(writer, peer.addr, addr_width);
        }
        try writer.writeAll("  ");
        try writePadded(writer, peerStateWord(peer.state), 11);
        try writer.writeAll("  ");
        try writeLeftPad(writer, rtt_writer.buffered(), 5);
        try writer.writeAll("  ");
        try writeLeftPad(writer, hops_writer.buffered(), 2);
        try writer.writeAll("  ");
        try writeLeftPad(writer, in_text, 8);
        try writer.writeAll("  ");
        try writeLeftPad(writer, out_text, 8);
        try writer.writeAll("  ");
        try writer.writeAll(since_text);
        try writer.writeByte('\n');
    }

    try writer.print("Summary: {d} peers, {d} established\n", .{ snap.peers.len, established });
}

fn formatSince(buf: []u8, since_unix: i64) []const u8 {
    if (since_unix <= 0) return "-";
    return formatDuration(buf, @intCast(since_unix));
}

fn formatDuration(buf: []u8, secs: u64) []const u8 {
    const days = secs / 86_400;
    const hours = (secs % 86_400) / 3_600;
    const mins = (secs % 3_600) / 60;
    const seconds = secs % 60;

    var w = std.Io.Writer.fixed(buf);
    if (days != 0) {
        w.print("{d}d {d:0>2}h", .{ days, hours }) catch return buf[0..0];
    } else if (hours != 0) {
        w.print("{d}h {d:0>2}m", .{ hours, mins }) catch return buf[0..0];
    } else if (mins != 0) {
        w.print("{d}m", .{mins}) catch return buf[0..0];
    } else {
        w.print("{d}s", .{seconds}) catch return buf[0..0];
    }
    return w.buffered();
}

fn visibleLen(s: []const u8) usize {
    var n: usize = 0;
    for (s) |c| {
        if (c != '\r' and c != '\n') n += 1;
    }
    return n;
}

fn writeClean(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        if (c != '\r' and c != '\n') try writer.writeByte(c);
    }
}

fn writePadded(writer: anytype, s: []const u8, width: usize) !void {
    try writer.writeAll(s);
    var remaining = width -| s.len;
    while (remaining != 0) : (remaining -= 1) try writer.writeByte(' ');
}

fn writeCleanPadded(writer: anytype, s: []const u8, width: usize) !void {
    try writeClean(writer, s);
    var remaining = width -| visibleLen(s);
    while (remaining != 0) : (remaining -= 1) try writer.writeByte(' ');
}

fn writeLeftPad(writer: anytype, s: []const u8, width: usize) !void {
    var remaining = width -| s.len;
    while (remaining != 0) : (remaining -= 1) try writer.writeByte(' ');
    try writer.writeAll(s);
}

fn renderToBuf(snap: MeshSnapshot, buf: []u8) ![]const u8 {
    var w = std.Io.Writer.fixed(buf);
    try renderMesh(snap, &w);
    return w.buffered();
}

test "empty mesh renders header columns and summary" {
    var buf: [1024]u8 = undefined;

    const out = try renderToBuf(.{
        .local_node = "local.example",
        .peers = &.{},
        .reachable_nodes = 1,
        .partitioned_nodes = 0,
    }, &buf);

    try std.testing.expect(std.mem.indexOf(u8, out, "MESH local=local.example reachable=1 partitioned=0 root=-\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "peer  addr  state") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Summary: 0 peers, 0 established\n") != null);
}

test "multiple peers render aligned state rtt hops byte and age fields" {
    const peers = [_]PeerLink{
        .{
            .name = "alpha.example",
            .addr = "10.0.0.2:6697",
            .state = .established,
            .rtt_ms = 42,
            .bytes_in = 1536,
            .bytes_out = 2 * 1024 * 1024,
            .since_unix = 300,
            .hops = 1,
        },
        .{
            .name = "beta",
            .addr = "mesh.beta",
            .state = .handshaking,
            .rtt_ms = 250,
            .bytes_in = 1023,
            .bytes_out = 1024,
            .since_unix = 2 * 86_400 + 3 * 3_600,
            .hops = 2,
        },
        .{
            .name = "gamma",
            .state = .down,
            .hops = 4,
        },
    };
    var buf: [2048]u8 = undefined;

    const out = try renderToBuf(.{
        .local_node = "local",
        .peers = &peers,
        .reachable_nodes = 3,
        .partitioned_nodes = 1,
        .root_hash_hex = "abc123",
    }, &buf);

    try std.testing.expect(std.mem.indexOf(u8, out, "MESH local=local reachable=3 partitioned=1 root=abc123\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "alpha.example") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "10.0.0.2:6697") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "established") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "42ms") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "1.5 KB") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "2.0 MB") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "5m") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "beta") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "mesh.beta") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "handshaking") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "250ms") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "1023 B") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "1.0 KB") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "2d 03h") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "gamma") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "down") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "Summary: 3 peers, 1 established\n") != null);
}

test "formatBytes covers binary unit boundaries" {
    var buf: [40]u8 = undefined;

    try std.testing.expectEqualStrings("1023 B", formatBytes(&buf, 1023));
    try std.testing.expectEqualStrings("1.0 KB", formatBytes(&buf, 1024));
    try std.testing.expectEqualStrings("1.0 MB", formatBytes(&buf, 1 << 20));
    try std.testing.expectEqualStrings("1.0 GB", formatBytes(&buf, 1 << 30));
    try std.testing.expectEqualStrings("1.5 KB", formatBytes(&buf, 1536));
}

test "peerStateWord returns lowercase state words" {
    try std.testing.expectEqualStrings("connecting", peerStateWord(.connecting));
    try std.testing.expectEqualStrings("handshaking", peerStateWord(.handshaking));
    try std.testing.expectEqualStrings("established", peerStateWord(.established));
    try std.testing.expectEqualStrings("draining", peerStateWord(.draining));
    try std.testing.expectEqualStrings("down", peerStateWord(.down));
}

test "rendered lines never contain carriage returns from input" {
    const peers = [_]PeerLink{.{
        .name = "bad\rname",
        .addr = "host\nname",
        .state = .draining,
        .since_unix = 30,
        .bytes_in = 1 << 30,
    }};
    var buf: [1024]u8 = undefined;

    const out = try renderToBuf(.{
        .local_node = "local\rnode",
        .peers = &peers,
        .root_hash_hex = "aa\rbb",
    }, &buf);

    try std.testing.expect(std.mem.indexOfScalar(u8, out, '\r') == null);
    try std.testing.expect(std.mem.indexOf(u8, out, "localnode") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "badname") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "hostname") != null);
}
