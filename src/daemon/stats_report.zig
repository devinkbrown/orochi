// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Web stats renderer — turns a server/channel statistics snapshot into a
//! modern JSON document and a self-contained HTML dashboard for static hosting
//! (e.g. an nginx `root` directory the daemon writes to periodically).
//!
//! This module is pure: it owns no state, performs no I/O, and reads no clock —
//! the caller assembles a `Snapshot` from live daemon state and passes a writer.
//! Both renderers escape untrusted strings (channel names, topics, server name)
//! so a crafted topic can never break out of the JSON/HTML it lands in.

const std = @import("std");

/// One channel row in the "busiest channels" table.
pub const TopChannel = struct {
    name: []const u8,
    members: u32,
    topic: []const u8 = "",
    /// Filename stem of this channel's detail page (without extension). When set,
    /// the channel name links to `chan_<slug>.html`.
    slug: []const u8 = "",
};

/// Aggregate client count for one country (ISO 3166-1 alpha-2 code).
pub const CountryCount = struct {
    /// Two-letter ISO country code (e.g. "US"); "??" when geo is unknown.
    code: []const u8,
    clients: u32,
};

/// Public node/mesh health summary shown on the stats index and stats.json.
pub const NodeHealth = struct {
    status: []const u8 = "ok",
    mesh_quorum: bool = true,
    mesh_partitioned: bool = false,
    mesh_components: u32 = 1,
    mesh_peers_up: u32 = 0,
    mesh_peers_total: u32 = 0,
};

/// One member row on a channel detail page.
pub const Member = struct {
    nick: []const u8,
    prefix: []const u8 = "",
};

/// A single channel's detail snapshot for its own page.
pub const ChannelDetail = struct {
    name: []const u8,
    topic: []const u8 = "",
    modes: []const u8 = "",
    member_count: u64 = 0,
    members: []const Member = &.{},
    generated_unix: i64 = 0,
};

/// A complete statistics snapshot. Counts are plain values; string slices are
/// borrowed for the duration of a render call.
pub const Snapshot = struct {
    server_name: []const u8,
    network: []const u8 = "",
    version: []const u8 = "",
    /// Unix-epoch seconds the snapshot was generated.
    generated_unix: i64 = 0,
    /// Seconds the server has been running.
    uptime_secs: u64 = 0,
    clients: u64 = 0,
    opers: u64 = 0,
    channels: u64 = 0,
    servers: u64 = 1,
    /// Highest simultaneous client count seen this run.
    max_clients: u64 = 0,
    /// Lifetime transport counters.
    connections_total: u64 = 0,
    messages_total: u64 = 0,
    bytes_in: u64 = 0,
    bytes_out: u64 = 0,
    node_health: NodeHealth = .{},
    /// Recent client-count samples, oldest first, for the sparkline.
    history: []const u32 = &.{},
    /// Busiest channels, already sorted by membership descending by the caller.
    top_channels: []const TopChannel = &.{},
    /// Client distribution by country, sorted by count descending by the caller.
    /// Empty when no GeoIP database is configured.
    top_countries: []const CountryCount = &.{},
};

// ── JSON ───────────────────────────────────────────────────────────────────

/// Render the snapshot as a compact, well-formed JSON object.
pub fn renderJson(snapshot: Snapshot, writer: anytype) !void {
    try writer.writeAll("{\n");
    try writer.writeAll("  \"server\": ");
    try jsonString(writer, snapshot.server_name);
    try writer.writeAll(",\n  \"network\": ");
    try jsonString(writer, snapshot.network);
    try writer.writeAll(",\n  \"version\": ");
    try jsonString(writer, snapshot.version);
    try writer.print(",\n  \"generated\": {d}", .{snapshot.generated_unix});
    try writer.print(",\n  \"uptime\": {d}", .{snapshot.uptime_secs});
    try writer.print(",\n  \"clients\": {d}", .{snapshot.clients});
    try writer.print(",\n  \"opers\": {d}", .{snapshot.opers});
    try writer.print(",\n  \"channels\": {d}", .{snapshot.channels});
    try writer.print(",\n  \"servers\": {d}", .{snapshot.servers});
    try writer.print(",\n  \"max_clients\": {d}", .{snapshot.max_clients});
    try writer.print(",\n  \"connections_total\": {d}", .{snapshot.connections_total});
    try writer.print(",\n  \"messages_total\": {d}", .{snapshot.messages_total});
    try writer.print(",\n  \"bytes_in\": {d}", .{snapshot.bytes_in});
    try writer.print(",\n  \"bytes_out\": {d}", .{snapshot.bytes_out});
    try writer.writeAll(",\n  \"node_health\": {\"status\": ");
    try jsonString(writer, snapshot.node_health.status);
    try writer.print(", \"mesh_quorum\": {s}, \"mesh_partitioned\": {s}, \"mesh_components\": {d}, \"mesh_peers_up\": {d}, \"mesh_peers_total\": {d}}}", .{
        if (snapshot.node_health.mesh_quorum) "true" else "false",
        if (snapshot.node_health.mesh_partitioned) "true" else "false",
        snapshot.node_health.mesh_components,
        snapshot.node_health.mesh_peers_up,
        snapshot.node_health.mesh_peers_total,
    });
    try writer.writeAll(",\n  \"history\": [");
    for (snapshot.history, 0..) |h, i| {
        if (i != 0) try writer.writeAll(", ");
        try writer.print("{d}", .{h});
    }
    try writer.writeAll("]");
    try writer.writeAll(",\n  \"top_channels\": [");
    for (snapshot.top_channels, 0..) |c, i| {
        if (i != 0) try writer.writeAll(",");
        try writer.writeAll("\n    {\"name\": ");
        try jsonString(writer, c.name);
        try writer.print(", \"members\": {d}, \"topic\": ", .{c.members});
        try jsonString(writer, c.topic);
        try writer.writeAll("}");
    }
    if (snapshot.top_channels.len != 0) try writer.writeAll("\n  ");
    try writer.writeAll("]");
    try writer.writeAll(",\n  \"top_countries\": [");
    for (snapshot.top_countries, 0..) |cc, i| {
        if (i != 0) try writer.writeAll(",");
        try writer.writeAll("\n    {\"code\": ");
        try jsonString(writer, cc.code);
        try writer.print(", \"clients\": {d}}}", .{cc.clients});
    }
    if (snapshot.top_countries.len != 0) try writer.writeAll("\n  ");
    try writer.writeAll("]\n}\n");
}

fn jsonString(writer: anytype, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0...0x08, 0x0b, 0x0c, 0x0e...0x1f => try writer.print("\\u{x:0>4}", .{c}),
            else => try writer.writeByte(c),
        }
    }
    try writer.writeByte('"');
}

// ── HTML ──────────────────────────────────────────────────────────────────

/// Render a self-contained HTML dashboard (inline CSS, no external assets) that
/// auto-refreshes. Suitable for static serving straight from disk.
pub fn renderHtml(snapshot: Snapshot, writer: anytype) !void {
    try writer.writeAll(
        \\<!DOCTYPE html>
        \\<html lang="en"><head><meta charset="utf-8">
        \\<meta name="viewport" content="width=device-width, initial-scale=1">
        \\<meta http-equiv="refresh" content="30">
        \\<title>
    );
    try htmlText(writer, snapshot.server_name);
    try writer.writeAll(" — stats</title>\n<style>\n");
    try writer.writeAll(css);
    try writer.writeAll("</style></head><body>\n<main>\n<header><h1>");
    try htmlText(writer, snapshot.server_name);
    try writer.writeAll("</h1><p class=\"sub\">");
    try htmlText(writer, snapshot.network);
    try writer.writeAll(" · ");
    try htmlText(writer, snapshot.version);
    try writer.writeAll("</p></header>\n<section class=\"grid\">\n");

    try statCard(writer, "Clients", snapshot.clients);
    try statCard(writer, "Channels", snapshot.channels);
    try statCard(writer, "Operators", snapshot.opers);
    try statCard(writer, "Servers", snapshot.servers);
    try textCard(writer, "Node health", snapshot.node_health.status);
    try textCard(writer, "Mesh quorum", if (snapshot.node_health.mesh_quorum) "held" else "lost");
    try pairCard(writer, "Mesh peers", snapshot.node_health.mesh_peers_up, snapshot.node_health.mesh_peers_total);
    try statCard(writer, "Peak clients", snapshot.max_clients);
    try uptimeCard(writer, snapshot.uptime_secs);

    try writer.writeAll("</section>\n");

    if (snapshot.history.len >= 2) {
        try writer.writeAll("<h2>Clients (recent)</h2>\n<div class=\"card spark\">");
        try sparkline(writer, snapshot.history);
        try writer.writeAll("</div>\n");
    }

    try writer.writeAll("<section class=\"grid\">\n");
    try statCard(writer, "Connections", snapshot.connections_total);
    try statCard(writer, "Messages", snapshot.messages_total);
    try byteCard(writer, "Bytes in", snapshot.bytes_in);
    try byteCard(writer, "Bytes out", snapshot.bytes_out);
    try writer.writeAll("</section>\n");

    if (snapshot.top_channels.len != 0) {
        try writer.writeAll("<h2>Busiest channels</h2>\n<table><thead><tr><th>Channel</th><th>Members</th><th>Topic</th></tr></thead><tbody>\n");
        for (snapshot.top_channels) |c| {
            try writer.writeAll("<tr><td class=\"chan\">");
            if (c.slug.len > 0) {
                try writer.writeAll("<a href=\"chan_");
                try htmlText(writer, c.slug);
                try writer.writeAll(".html\">");
                try htmlText(writer, c.name);
                try writer.writeAll("</a>");
            } else {
                try htmlText(writer, c.name);
            }
            try writer.print("</td><td class=\"num\">{d}</td><td class=\"topic\">", .{c.members});
            try htmlText(writer, c.topic);
            try writer.writeAll("</td></tr>\n");
        }
        try writer.writeAll("</tbody></table>\n");
    }

    if (snapshot.top_countries.len != 0) {
        try writer.writeAll("<h2>Clients by country</h2>\n<table><thead><tr><th>Country</th><th>Clients</th></tr></thead><tbody>\n");
        for (snapshot.top_countries) |cc| {
            try writer.writeAll("<tr><td class=\"chan\">");
            try htmlText(writer, cc.code);
            try writer.print("</td><td class=\"num\">{d}</td></tr>\n", .{cc.clients});
        }
        try writer.writeAll("</tbody></table>\n");
    }

    try writer.print("<footer>generated at unix {d} · refreshes every 30s</footer>\n", .{snapshot.generated_unix});
    try writer.writeAll("</main></body></html>\n");
}

/// Render a single channel's detail page (topic, modes, member roster).
pub fn renderChannelHtml(detail: ChannelDetail, writer: anytype) !void {
    try writer.writeAll(
        \\<!DOCTYPE html>
        \\<html lang="en"><head><meta charset="utf-8">
        \\<meta name="viewport" content="width=device-width, initial-scale=1">
        \\<meta http-equiv="refresh" content="30">
        \\<title>
    );
    try htmlText(writer, detail.name);
    try writer.writeAll("</title>\n<style>\n");
    try writer.writeAll(css);
    try writer.writeAll("</style></head><body>\n<main>\n<header><h1>");
    try htmlText(writer, detail.name);
    try writer.writeAll("</h1><p class=\"sub\"><a href=\"index.html\">← all channels</a></p></header>\n");

    try writer.writeAll("<section class=\"grid\">\n");
    try statCard(writer, "Members", detail.member_count);
    try writer.writeAll("<div class=\"card\"><div class=\"v\">");
    if (detail.modes.len > 0) try htmlText(writer, detail.modes) else try writer.writeAll("—");
    try writer.writeAll("</div><div class=\"l\">Modes</div></div>\n</section>\n");

    if (detail.topic.len > 0) {
        try writer.writeAll("<h2>Topic</h2>\n<div class=\"card\">");
        try htmlText(writer, detail.topic);
        try writer.writeAll("</div>\n");
    }

    if (detail.members.len > 0) {
        try writer.writeAll("<h2>Members</h2>\n<table><tbody>\n");
        for (detail.members) |m| {
            try writer.writeAll("<tr><td class=\"chan\">");
            try htmlText(writer, m.prefix);
            try htmlText(writer, m.nick);
            try writer.writeAll("</td></tr>\n");
        }
        try writer.writeAll("</tbody></table>\n");
    }

    try writer.print("<footer>generated at unix {d} · refreshes every 30s</footer>\n", .{detail.generated_unix});
    try writer.writeAll("</main></body></html>\n");
}

fn statCard(writer: anytype, label: []const u8, value: u64) !void {
    try writer.print("<div class=\"card\"><div class=\"v\">{d}</div><div class=\"l\">{s}</div></div>\n", .{ value, label });
}

fn uptimeCard(writer: anytype, secs: u64) !void {
    const d = secs / 86400;
    const h = (secs % 86400) / 3600;
    const m = (secs % 3600) / 60;
    try writer.print("<div class=\"card\"><div class=\"v\">{d}d {d}h {d}m</div><div class=\"l\">Uptime</div></div>\n", .{ d, h, m });
}

fn byteCard(writer: anytype, label: []const u8, bytes: u64) !void {
    var v: f64 = @floatFromInt(bytes);
    const units = [_][]const u8{ "B", "KB", "MB", "GB", "TB", "PB" };
    var u: usize = 0;
    while (v >= 1024 and u + 1 < units.len) : (u += 1) v /= 1024;
    try writer.print("<div class=\"card\"><div class=\"v\">{d:.1} {s}</div><div class=\"l\">{s}</div></div>\n", .{ v, units[u], label });
}

fn textCard(writer: anytype, label: []const u8, value: []const u8) !void {
    try writer.writeAll("<div class=\"card\"><div class=\"v\">");
    try htmlText(writer, value);
    try writer.print("</div><div class=\"l\">{s}</div></div>\n", .{label});
}

fn pairCard(writer: anytype, label: []const u8, value: u32, total: u32) !void {
    try writer.print("<div class=\"card\"><div class=\"v\">{d}/{d}</div><div class=\"l\">{s}</div></div>\n", .{ value, total, label });
}

/// Inline, dependency-free SVG sparkline. `data` is oldest→newest; the viewBox
/// stretches to the card width via preserveAspectRatio="none".
fn sparkline(writer: anytype, data: []const u32) !void {
    var maxv: u32 = 1;
    for (data) |v| {
        if (v > maxv) maxv = v;
    }
    const w: usize = (data.len - 1) * 10;
    try writer.print("<svg viewBox=\"0 0 {d} 40\" preserveAspectRatio=\"none\" class=\"sl\"><polyline points=\"", .{w});
    for (data, 0..) |v, i| {
        if (i != 0) try writer.writeByte(' ');
        const y = 40 - (@as(usize, v) * 40) / maxv;
        try writer.print("{d},{d}", .{ i * 10, y });
    }
    try writer.writeAll("\"/></svg>");
}

fn htmlText(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '&' => try writer.writeAll("&amp;"),
            '<' => try writer.writeAll("&lt;"),
            '>' => try writer.writeAll("&gt;"),
            '"' => try writer.writeAll("&quot;"),
            '\'' => try writer.writeAll("&#39;"),
            else => try writer.writeByte(c),
        }
    }
}

const css =
    \\:root{color-scheme:dark}
    \\*{box-sizing:border-box}
    \\body{margin:0;font:15px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
    \\background:#0b0e14;color:#d7dce5}
    \\main{max-width:960px;margin:0 auto;padding:32px 20px}
    \\header h1{margin:0;font-size:28px;letter-spacing:-.02em}
    \\.sub{margin:4px 0 0;color:#7d8597}
    \\.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:24px 0}
    \\.card{background:#141925;border:1px solid #222a3a;border-radius:14px;padding:18px}
    \\.card .v{font-size:26px;font-weight:600;color:#fff}
    \\.card .l{margin-top:4px;color:#7d8597;font-size:13px;text-transform:uppercase;letter-spacing:.04em}
    \\h2{margin:28px 0 12px;font-size:18px}
    \\table{width:100%;border-collapse:collapse;background:#141925;border:1px solid #222a3a;border-radius:14px;overflow:hidden}
    \\th,td{padding:10px 14px;text-align:left;border-bottom:1px solid #222a3a}
    \\th{color:#7d8597;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
    \\tr:last-child td{border-bottom:none}
    \\.chan{color:#6ea8fe;font-weight:600}
    \\.num{text-align:right;font-variant-numeric:tabular-nums}
    \\.topic{color:#9aa3b2;max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    \\.spark{padding:14px;margin:12px 0}
    \\.sl{width:100%;height:56px;display:block}
    \\.sl polyline{fill:none;stroke:#6ea8fe;stroke-width:1.5;vector-effect:non-scaling-stroke}
    \\footer{margin-top:24px;color:#566072;font-size:12px}
;

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

var test_buf: [32 * 1024]u8 = undefined;

fn renderToBuf(comptime f: anytype, input: anytype) ![]const u8 {
    var w = std.Io.Writer.fixed(&test_buf);
    try f(input, &w);
    return w.buffered();
}

test "renderJson emits well-formed, escaped JSON" {
    const chans = [_]TopChannel{.{ .name = "#ops", .members = 12, .topic = "a \"quote\" & <tag>" }};
    const snap = Snapshot{
        .server_name = "suzu.example",
        .network = "Onyx",
        .version = "onyx-server-0.1",
        .generated_unix = 1700000000,
        .uptime_secs = 3661,
        .clients = 42,
        .opers = 3,
        .channels = 7,
        .max_clients = 99,
        .top_channels = &chans,
    };
    const json = try renderToBuf(renderJson, snap);

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expectEqualStrings("suzu.example", root.get("server").?.string);
    try testing.expectEqual(@as(i64, 42), root.get("clients").?.integer);
    const top = root.get("top_channels").?.array;
    try testing.expectEqual(@as(usize, 1), top.items.len);
    try testing.expectEqualStrings("#ops", top.items[0].object.get("name").?.string);
    try testing.expectEqualStrings("a \"quote\" & <tag>", top.items[0].object.get("topic").?.string);
}

test "renderHtml escapes and contains the key figures" {
    const chans = [_]TopChannel{.{ .name = "#a", .members = 5, .topic = "<script>" }};
    const snap = Snapshot{ .server_name = "s<x>", .clients = 10, .channels = 2, .top_channels = &chans };
    const html = try renderToBuf(renderHtml, snap);

    try testing.expect(std.mem.indexOf(u8, html, "<!DOCTYPE html>") != null);
    try testing.expect(std.mem.indexOf(u8, html, "s&lt;x&gt;") != null); // server name escaped
    try testing.expect(std.mem.indexOf(u8, html, "&lt;script&gt;") != null); // topic escaped
    try testing.expect(std.mem.indexOf(u8, html, "<script>") == null); // never raw
    try testing.expect(std.mem.indexOf(u8, html, ">10<") != null); // client count rendered
}

test "renderHtml emits a sparkline, transport cards, and channel links" {
    const hist = [_]u32{ 1, 4, 2, 8 };
    const chans = [_]TopChannel{.{ .name = "#a", .members = 5, .slug = "_a" }};
    const snap = Snapshot{
        .server_name = "s",
        .bytes_in = 2048,
        .messages_total = 9,
        .history = &hist,
        .top_channels = &chans,
    };
    const html = try renderToBuf(renderHtml, snap);
    try testing.expect(std.mem.indexOf(u8, html, "<polyline points=") != null);
    try testing.expect(std.mem.indexOf(u8, html, "2.0 KB") != null); // byte card
    try testing.expect(std.mem.indexOf(u8, html, "href=\"chan__a.html\"") != null); // channel link
}

test "country distribution renders in JSON and HTML" {
    const ctry = [_]CountryCount{ .{ .code = "US", .clients = 8 }, .{ .code = "DE", .clients = 3 } };
    const snap = Snapshot{ .server_name = "s", .clients = 11, .top_countries = &ctry };

    const json = try renderToBuf(renderJson, snap);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
    defer parsed.deinit();
    const arr = parsed.value.object.get("top_countries").?.array;
    try testing.expectEqual(@as(usize, 2), arr.items.len);
    try testing.expectEqualStrings("US", arr.items[0].object.get("code").?.string);
    try testing.expectEqual(@as(i64, 8), arr.items[0].object.get("clients").?.integer);

    const html = try renderToBuf(renderHtml, snap);
    try testing.expect(std.mem.indexOf(u8, html, "Clients by country") != null);
    try testing.expect(std.mem.indexOf(u8, html, ">US<") != null);
}

test "node health renders in JSON and stats index" {
    const snap = Snapshot{
        .server_name = "s",
        .node_health = .{
            .status = "degraded",
            .mesh_quorum = false,
            .mesh_partitioned = true,
            .mesh_components = 2,
            .mesh_peers_up = 1,
            .mesh_peers_total = 3,
        },
    };

    const json = try renderToBuf(renderJson, snap);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
    defer parsed.deinit();
    const health = parsed.value.object.get("node_health").?.object;
    try testing.expectEqualStrings("degraded", health.get("status").?.string);
    try testing.expect(!health.get("mesh_quorum").?.bool);
    try testing.expect(health.get("mesh_partitioned").?.bool);
    try testing.expectEqual(@as(i64, 2), health.get("mesh_components").?.integer);
    try testing.expectEqual(@as(i64, 1), health.get("mesh_peers_up").?.integer);
    try testing.expectEqual(@as(i64, 3), health.get("mesh_peers_total").?.integer);

    const html = try renderToBuf(renderHtml, snap);
    try testing.expect(std.mem.indexOf(u8, html, "Node health") != null);
    try testing.expect(std.mem.indexOf(u8, html, "degraded") != null);
    try testing.expect(std.mem.indexOf(u8, html, "1/3") != null);
}

test "renderChannelHtml lists members and escapes" {
    const members = [_]Member{ .{ .nick = "alice", .prefix = "@" }, .{ .nick = "b<ob>" } };
    const detail = ChannelDetail{
        .name = "#ops",
        .topic = "<hi>",
        .modes = "+mnt",
        .member_count = 2,
        .members = &members,
    };
    const html = try renderToBuf(renderChannelHtml, detail);
    try testing.expect(std.mem.indexOf(u8, html, "@alice") != null);
    try testing.expect(std.mem.indexOf(u8, html, "b&lt;ob&gt;") != null);
    try testing.expect(std.mem.indexOf(u8, html, "&lt;hi&gt;") != null); // topic escaped
    try testing.expect(std.mem.indexOf(u8, html, "all channels") != null);
}

test "empty snapshot renders valid JSON with empty channel list" {
    const json = try renderToBuf(renderJson, Snapshot{ .server_name = "x" });
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 0), parsed.value.object.get("top_channels").?.array.items.len);
}
