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
    /// Busiest channels, already sorted by membership descending by the caller.
    top_channels: []const TopChannel = &.{},
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
    try statCard(writer, "Peak clients", snapshot.max_clients);
    try uptimeCard(writer, snapshot.uptime_secs);

    try writer.writeAll("</section>\n");

    if (snapshot.top_channels.len != 0) {
        try writer.writeAll("<h2>Busiest channels</h2>\n<table><thead><tr><th>Channel</th><th>Members</th><th>Topic</th></tr></thead><tbody>\n");
        for (snapshot.top_channels) |c| {
            try writer.writeAll("<tr><td class=\"chan\">");
            try htmlText(writer, c.name);
            try writer.print("</td><td class=\"num\">{d}</td><td class=\"topic\">", .{c.members});
            try htmlText(writer, c.topic);
            try writer.writeAll("</td></tr>\n");
        }
        try writer.writeAll("</tbody></table>\n");
    }

    try writer.print("<footer>generated at unix {d} · refreshes every 30s</footer>\n", .{snapshot.generated_unix});
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
    \\footer{margin-top:24px;color:#566072;font-size:12px}
;

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

var test_buf: [32 * 1024]u8 = undefined;

fn renderToBuf(comptime f: anytype, snapshot: Snapshot) ![]const u8 {
    var w = std.Io.Writer.fixed(&test_buf);
    try f(snapshot, &w);
    return w.buffered();
}

test "renderJson emits well-formed, escaped JSON" {
    const chans = [_]TopChannel{.{ .name = "#ops", .members = 12, .topic = "a \"quote\" & <tag>" }};
    const snap = Snapshot{
        .server_name = "mizu.example",
        .network = "Mizuchi",
        .version = "mizuchi-0.1",
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
    try testing.expectEqualStrings("mizu.example", root.get("server").?.string);
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

test "empty snapshot renders valid JSON with empty channel list" {
    const json = try renderToBuf(renderJson, .{ .server_name = "x" });
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 0), parsed.value.object.get("top_channels").?.array.items.len);
}
