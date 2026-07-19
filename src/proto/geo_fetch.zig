// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Key-free weather + news acquisition: HTTP/1.1 request builders and response
//! parsers for two no-API-key sources.
//!
//!   * Weather — `wttr.in`, plain HTTP, custom one-line format
//!     (`?format=%t|%w|%C|%l&m`) yielding e.g. `+33°C|↑21km/h|Partly cloudy|Austin`.
//!     Metric is forced (`&m`) so callers can re-localize per the requesting
//!     user's country via `weather_units`.
//!   * News — any RSS/Atom feed (e.g. a public news RSS), parsing `<title>`
//!     elements (the feed's own title is the first one and is skipped).
//!
//! This module is pure `std`: it builds request bytes into caller storage and
//! parses response bodies into slices that borrow the input. The actual socket
//! I/O lives in `daemon/geo_services.zig` (a background thread), so nothing here
//! blocks or allocates.
const std = @import("std");
const weather_units = @import("weather_units.zig");

pub const Error = error{
    BufferTooSmall,
    InvalidLocation,
    ParseFailed,
};

/// Default weather host. Plain HTTP (no TLS, no key) is supported by wttr.in.
pub const weather_host = "wttr.in";

/// A parsed wttr.in reading plus its echoed location, borrowing the response
/// body. Numbers are metric so the caller localizes via `weather_units`.
pub const Weather = struct {
    reading: weather_units.Reading,
    location: []const u8,
};

/// Bounded append cursor over caller storage. Every write is length-checked so
/// request construction never overflows on attacker-influenced input.
const Cursor = struct {
    buf: []u8,
    len: usize = 0,

    fn write(self: *Cursor, s: []const u8) Error!void {
        if (self.len + s.len > self.buf.len) return error.BufferTooSmall;
        @memcpy(self.buf[self.len .. self.len + s.len], s);
        self.len += s.len;
    }

    fn byte(self: *Cursor, b: u8) Error!void {
        if (self.len + 1 > self.buf.len) return error.BufferTooSmall;
        self.buf[self.len] = b;
        self.len += 1;
    }

    fn hexByte(self: *Cursor, b: u8) Error!void {
        const hex = "0123456789ABCDEF";
        try self.byte('%');
        try self.byte(hex[b >> 4]);
        try self.byte(hex[b & 0x0f]);
    }

    fn written(self: *const Cursor) []const u8 {
        return self.buf[0..self.len];
    }
};

/// Build a GET request for `http://<host>/<location>?format=%t|%w|%C|%l&m`.
/// The location path segment is percent-encoded; the literal `%`/`|` in the
/// format query are passed through (wttr.in accepts them raw).
pub fn buildWeatherRequest(buf: []u8, host: []const u8, location: []const u8) Error![]const u8 {
    if (location.len == 0) return error.InvalidLocation;
    var c = Cursor{ .buf = buf };
    try c.write("GET /");
    try writePercentEncoded(&c, location);
    // %t=temp %w=wind %C=condition %l=location; &m forces metric units.
    try c.write("?format=%t|%w|%C|%l&m HTTP/1.1\r\nHost: ");
    try c.write(host);
    // wttr.in serves the one-line body to curl-like User-Agents.
    try c.write("\r\nUser-Agent: curl/8\r\nAccept: text/plain\r\nConnection: close\r\n\r\n");
    return c.written();
}

/// Build a GET request for an arbitrary RSS feed path on `host`.
pub fn buildNewsRequest(buf: []u8, host: []const u8, path: []const u8) Error![]const u8 {
    var c = Cursor{ .buf = buf };
    try c.write("GET ");
    try c.write(if (path.len == 0) "/" else path);
    try c.write(" HTTP/1.1\r\nHost: ");
    try c.write(host);
    try c.write("\r\nUser-Agent: onyx-server-news/1\r\nAccept: application/rss+xml, application/xml, text/xml\r\nConnection: close\r\n\r\n");
    return c.written();
}

/// Return the body of an HTTP response (everything after the CRLFCRLF header
/// terminator). Returns the whole input if no terminator is present.
pub fn httpBody(response: []const u8) []const u8 {
    if (std.mem.indexOf(u8, response, "\r\n\r\n")) |i| return response[i + 4 ..];
    if (std.mem.indexOf(u8, response, "\n\n")) |i| return response[i + 2 ..];
    return response;
}

/// Parse a wttr.in one-line body (`+33°C|↑21km/h|Partly cloudy|Austin`) into a
/// metric `Weather`. Tolerates trailing whitespace/newlines and missing fields.
pub fn parseWeather(body: []const u8) Error!Weather {
    const line = firstLine(body);
    if (line.len == 0) return error.ParseFailed;

    var it = std.mem.splitScalar(u8, line, '|');
    const temp_field = it.next() orelse return error.ParseFailed;
    const wind_field = it.next() orelse "";
    const desc_field = it.next() orelse "";
    const loc_field = it.next() orelse "";

    const temp_c = parseLeadingNumber(temp_field) orelse return error.ParseFailed;
    const wind_kph = parseLeadingNumber(wind_field) orelse 0;

    return .{
        .reading = .{
            .temp_c = temp_c,
            .wind_kph = wind_kph,
            .precip_mm = 0,
            .desc = std.mem.trim(u8, desc_field, " \t\r\n"),
        },
        .location = std.mem.trim(u8, loc_field, " \t\r\n"),
    };
}

/// Extract up to `out.len` headline titles from an RSS/Atom body. Only the first
/// `<title>` *inside each `<item>` (RSS) or `<entry>` (Atom)* is taken, so the
/// channel/feed and `<image>` titles are never mistaken for headlines. CDATA
/// wrappers are unwrapped; titles are emitted verbatim (trimmed). Returned slices
/// borrow `body`. Returns the filled prefix of `out`.
pub fn parseRssTitles(body: []const u8, out: [][]const u8) [][]const u8 {
    var count: usize = 0;
    var cursor: usize = 0;
    while (count < out.len) {
        // Advance to the next item/entry element.
        const item = nextItemStart(body, cursor) orelse break;
        // Bound the search to this item so we take its own <title>, not a later one.
        const item_end = itemEnd(body, item.content_start);
        cursor = item_end;

        const region = body[item.content_start..item_end];
        const title = firstTitle(region) orelse continue;
        if (title.len == 0) continue;
        out[count] = title;
        count += 1;
    }
    return out[0..count];
}

const ItemStart = struct { content_start: usize };

/// Find the next `<item`/`<entry` element opening at or after `from`.
fn nextItemStart(body: []const u8, from: usize) ?ItemStart {
    var best: ?usize = null;
    inline for (.{ "<item", "<entry" }) |tag| {
        if (std.mem.indexOf(u8, body[from..], tag)) |rel| {
            const at = from + rel;
            if (best == null or at < best.?) best = at;
        }
    }
    const open = best orelse return null;
    const gt_rel = std.mem.indexOfScalar(u8, body[open..], '>') orelse return null;
    return .{ .content_start = open + gt_rel + 1 };
}

/// End offset of the item beginning at `start` (its closing tag or EOF).
fn itemEnd(body: []const u8, start: usize) usize {
    var end = body.len;
    inline for (.{ "</item>", "</entry>" }) |tag| {
        if (std.mem.indexOf(u8, body[start..], tag)) |rel| {
            const at = start + rel;
            if (at < end) end = at;
        }
    }
    return end;
}

/// First `<title>...</title>` content within `region`, CDATA-unwrapped + trimmed.
fn firstTitle(region: []const u8) ?[]const u8 {
    const open = std.mem.indexOf(u8, region, "<title") orelse return null;
    const gt_rel = std.mem.indexOfScalar(u8, region[open..], '>') orelse return null;
    const content_start = open + gt_rel + 1;
    const close_rel = std.mem.indexOf(u8, region[content_start..], "</title>") orelse return null;
    const raw = region[content_start .. content_start + close_rel];
    return std.mem.trim(u8, unwrapCdata(std.mem.trim(u8, raw, " \t\r\n")), " \t\r\n");
}

// ---- internals --------------------------------------------------------------

fn unwrapCdata(s: []const u8) []const u8 {
    const open = "<![CDATA[";
    const close = "]]>";
    if (std.mem.startsWith(u8, s, open) and std.mem.endsWith(u8, s, close)) {
        return s[open.len .. s.len - close.len];
    }
    return s;
}

fn firstLine(s: []const u8) []const u8 {
    const trimmed = std.mem.trimStart(u8, s, " \t\r\n");
    const end = std.mem.indexOfScalar(u8, trimmed, '\n') orelse trimmed.len;
    return std.mem.trim(u8, trimmed[0..end], " \t\r\n");
}

/// Parse the first signed decimal number embedded in `s` (skipping a leading
/// direction arrow or '+'), e.g. "+33°C" -> 33, "↑21km/h" -> 21, "-4°C" -> -4.
fn parseLeadingNumber(s: []const u8) ?f64 {
    var i: usize = 0;
    // Find the first digit or a sign immediately preceding a digit.
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == '-' or c == '+') {
            if (i + 1 < s.len and isDigit(s[i + 1])) break;
        } else if (isDigit(c)) {
            break;
        }
    }
    if (i >= s.len) return null;
    var j = i;
    if (s[j] == '-' or s[j] == '+') j += 1;
    while (j < s.len and (isDigit(s[j]) or s[j] == '.')) j += 1;
    return std.fmt.parseFloat(f64, s[i..j]) catch null;
}

fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}

/// Percent-encode everything except RFC 3986 unreserved characters, so a free
/// text location ("San Francisco") is a valid single path segment.
fn writePercentEncoded(c: *Cursor, s: []const u8) Error!void {
    for (s) |ch| {
        if (isUnreserved(ch)) {
            try c.byte(ch);
        } else {
            try c.hexByte(ch);
        }
    }
}

fn isUnreserved(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or
        (c >= '0' and c <= '9') or c == '-' or c == '_' or c == '.' or c == '~' or c == ',';
}

// ---- tests ------------------------------------------------------------------

test "buildWeatherRequest percent-encodes the location and forces metric" {
    var buf: [256]u8 = undefined;
    const req = try buildWeatherRequest(&buf, weather_host, "San Francisco");
    try std.testing.expect(std.mem.startsWith(u8, req, "GET /San%20Francisco?format=%t|%w|%C|%l&m HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, req, "Host: wttr.in\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, req, "\r\n\r\n"));
}

test "buildWeatherRequest rejects an empty location" {
    var buf: [64]u8 = undefined;
    try std.testing.expectError(error.InvalidLocation, buildWeatherRequest(&buf, weather_host, ""));
}

test "parseWeather parses a wttr.in one-line body (metric)" {
    const w = try parseWeather("+33°C|↑21km/h|Partly cloudy|Austin\n");
    try std.testing.expectEqual(@as(f64, 33), w.reading.temp_c);
    try std.testing.expectEqual(@as(f64, 21), w.reading.wind_kph);
    try std.testing.expectEqualStrings("Partly cloudy", w.reading.desc);
    try std.testing.expectEqualStrings("Austin", w.location);
}

test "parseWeather handles a negative temperature and missing fields" {
    const w = try parseWeather("-4°C|↓7km/h|Snow|Oslo");
    try std.testing.expectEqual(@as(f64, -4), w.reading.temp_c);
    try std.testing.expectEqual(@as(f64, 7), w.reading.wind_kph);
    try std.testing.expectEqualStrings("Snow", w.reading.desc);
}

test "parseWeather then localize to US imperial round-trips through weather_units" {
    const w = try parseWeather("+22°C|↑20km/h|Partly cloudy|Austin");
    var buf: [128]u8 = undefined;
    const line = weather_units.renderLine(&buf, w.location, w.reading, weather_units.forCountry("US"));
    try std.testing.expectEqualStrings("Austin: 72°F, Partly cloudy, wind 12 mph", line);
}

test "parseRssTitles skips the feed title and returns headlines" {
    const body =
        \\<?xml version="1.0"?><rss><channel>
        \\<title>Example News</title>
        \\<item><title>First headline</title></item>
        \\<item><title><![CDATA[Second & headline]]></title></item>
        \\<item><title>Third headline</title></item>
        \\</channel></rss>
    ;
    var out: [2][]const u8 = undefined;
    const titles = parseRssTitles(body, &out);
    try std.testing.expectEqual(@as(usize, 2), titles.len);
    try std.testing.expectEqualStrings("First headline", titles[0]);
    try std.testing.expectEqualStrings("Second & headline", titles[1]);
}

test "httpBody splits on the header terminator" {
    const resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n+10°C|↑5km/h|Clear|Paris";
    try std.testing.expectEqualStrings("+10°C|↑5km/h|Clear|Paris", httpBody(resp));
}
