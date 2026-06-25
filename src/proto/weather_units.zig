// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Locale-correct weather unit formatting.
//!
//! Weather readings are stored canonically in metric (°C, km/h, mm) and rendered
//! into the units a given country/region actually uses, so a US client sees
//! "72°F, wind 8 mph" while a French client sees "22°C, vent 13 km/h" from the
//! same reading. Pure `std`, allocation-free (caller supplies the buffer);
//! natively unit-tested.
const std = @import("std");

/// The unit convention to render with.
///   * metric   — °C, km/h, mm        (most of the world)
///   * imperial — °F, mph, in         (US + a handful of territories)
///   * uk       — °C, mph, mm         (UK: metric temperature, imperial wind)
pub const UnitSystem = enum { metric, imperial, uk };

/// Pick the unit system for an ISO 3166-1 alpha-2 country code (case-insensitive).
/// US states all map to `imperial` via the "US" code. Unknown codes default to
/// metric (the global norm).
pub fn forCountry(cc: []const u8) UnitSystem {
    var up: [2]u8 = .{ ' ', ' ' };
    if (cc.len >= 1) up[0] = std.ascii.toUpper(cc[0]);
    if (cc.len >= 2) up[1] = std.ascii.toUpper(cc[1]);
    const code = up[0..2];

    // United Kingdom: Celsius temperatures but miles-per-hour winds.
    if (std.mem.eql(u8, code, "GB") or std.mem.eql(u8, code, "UK")) return .uk;

    // Countries that report weather in imperial units (US + small territories
    // that follow US conventions).
    const imperial_codes = [_][]const u8{ "US", "BS", "BZ", "KY", "PW", "FM", "MH", "LR" };
    for (imperial_codes) |ic| {
        if (std.mem.eql(u8, code, ic)) return .imperial;
    }
    return .metric;
}

/// A canonical (metric) weather reading.
pub const Reading = struct {
    temp_c: f64 = 0,
    wind_kph: f64 = 0,
    precip_mm: f64 = 0,
    /// Free-text condition (e.g. "Partly cloudy"); rendered verbatim.
    desc: []const u8 = "",
};

fn roundI(v: f64) i64 {
    return @intFromFloat(@round(v));
}

/// Format a temperature into `buf`, e.g. "72°F" or "22°C".
pub fn formatTemp(temp_c: f64, sys: UnitSystem, buf: []u8) []const u8 {
    return switch (sys) {
        .imperial => std.fmt.bufPrint(buf, "{d}°F", .{roundI(temp_c * 9.0 / 5.0 + 32.0)}) catch buf[0..0],
        .metric, .uk => std.fmt.bufPrint(buf, "{d}°C", .{roundI(temp_c)}) catch buf[0..0],
    };
}

/// Format a wind speed into `buf`, e.g. "8 mph" or "13 km/h".
pub fn formatWind(wind_kph: f64, sys: UnitSystem, buf: []u8) []const u8 {
    return switch (sys) {
        .imperial, .uk => std.fmt.bufPrint(buf, "{d} mph", .{roundI(wind_kph * 0.621371)}) catch buf[0..0],
        .metric => std.fmt.bufPrint(buf, "{d} km/h", .{roundI(wind_kph)}) catch buf[0..0],
    };
}

/// Format a precipitation amount into `buf`, e.g. "0.2 in" or "5 mm".
pub fn formatPrecip(precip_mm: f64, sys: UnitSystem, buf: []u8) []const u8 {
    return switch (sys) {
        .imperial => std.fmt.bufPrint(buf, "{d:.2} in", .{precip_mm / 25.4}) catch buf[0..0],
        .metric, .uk => std.fmt.bufPrint(buf, "{d} mm", .{roundI(precip_mm)}) catch buf[0..0],
    };
}

/// Resolve a unit system from a config override and a country code. `units` is
/// one of "metric"/"imperial"/"uk"; anything else (incl. "auto"/"") falls back
/// to the country mapping.
pub fn resolveSystem(units: []const u8, country: []const u8) UnitSystem {
    if (std.ascii.eqlIgnoreCase(units, "metric")) return .metric;
    if (std.ascii.eqlIgnoreCase(units, "imperial")) return .imperial;
    if (std.ascii.eqlIgnoreCase(units, "uk")) return .uk;
    return forCountry(country);
}

/// A weather reading parsed from a source file, with its location/country.
pub const Forecast = struct {
    reading: Reading = .{},
    location: []const u8 = "",
    country: []const u8 = "",
};

/// Parse a simple `key=value` source file (one pair per line) into a `Forecast`.
/// Recognized keys: temp_c, wind_kph, precip_mm, desc, location, country.
/// Unknown keys and malformed numbers are ignored; slices borrow `text`.
pub fn parseForecast(text: []const u8) Forecast {
    var f = Forecast{};
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const val = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (std.mem.eql(u8, key, "temp_c")) {
            f.reading.temp_c = std.fmt.parseFloat(f64, val) catch f.reading.temp_c;
        } else if (std.mem.eql(u8, key, "wind_kph")) {
            f.reading.wind_kph = std.fmt.parseFloat(f64, val) catch f.reading.wind_kph;
        } else if (std.mem.eql(u8, key, "precip_mm")) {
            f.reading.precip_mm = std.fmt.parseFloat(f64, val) catch f.reading.precip_mm;
        } else if (std.mem.eql(u8, key, "desc")) {
            f.reading.desc = val;
        } else if (std.mem.eql(u8, key, "location")) {
            f.location = val;
        } else if (std.mem.eql(u8, key, "country")) {
            f.country = val;
        }
    }
    return f;
}

/// Render a one-line localized weather summary into `buf`, e.g.
/// "Austin: 72°F, Partly cloudy, wind 8 mph". An empty `desc` is omitted.
pub fn renderLine(buf: []u8, location: []const u8, reading: Reading, sys: UnitSystem) []const u8 {
    var tb: [16]u8 = undefined;
    var wb: [16]u8 = undefined;
    const temp = formatTemp(reading.temp_c, sys, &tb);
    const wind = formatWind(reading.wind_kph, sys, &wb);
    if (reading.desc.len != 0) {
        return std.fmt.bufPrint(buf, "{s}: {s}, {s}, wind {s}", .{ location, temp, reading.desc, wind }) catch buf[0..0];
    }
    return std.fmt.bufPrint(buf, "{s}: {s}, wind {s}", .{ location, temp, wind }) catch buf[0..0];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "country code maps to the right unit system" {
    try testing.expectEqual(UnitSystem.imperial, forCountry("US"));
    try testing.expectEqual(UnitSystem.imperial, forCountry("us"));
    try testing.expectEqual(UnitSystem.uk, forCountry("GB"));
    try testing.expectEqual(UnitSystem.uk, forCountry("uk"));
    try testing.expectEqual(UnitSystem.metric, forCountry("FR"));
    try testing.expectEqual(UnitSystem.metric, forCountry("JP"));
    try testing.expectEqual(UnitSystem.metric, forCountry(""));
}

test "temperature renders per system" {
    var b: [16]u8 = undefined;
    try testing.expectEqualStrings("22°C", formatTemp(22.0, .metric, &b));
    try testing.expectEqualStrings("22°C", formatTemp(22.0, .uk, &b));
    try testing.expectEqualStrings("72°F", formatTemp(22.0, .imperial, &b)); // 22C ≈ 71.6 -> 72
    try testing.expectEqualStrings("32°F", formatTemp(0.0, .imperial, &b));
}

test "wind renders per system, including the UK mph quirk" {
    var b: [16]u8 = undefined;
    try testing.expectEqualStrings("20 km/h", formatWind(20.0, .metric, &b));
    try testing.expectEqualStrings("12 mph", formatWind(20.0, .imperial, &b)); // 20kph ≈ 12.4 -> 12
    try testing.expectEqualStrings("12 mph", formatWind(20.0, .uk, &b));
}

test "precip renders per system" {
    var b: [16]u8 = undefined;
    try testing.expectEqualStrings("5 mm", formatPrecip(5.0, .metric, &b));
    try testing.expectEqualStrings("0.20 in", formatPrecip(5.08, .imperial, &b));
}

test "renderLine produces a localized one-liner" {
    var b: [128]u8 = undefined;
    const r = Reading{ .temp_c = 22.0, .wind_kph = 20.0, .desc = "Partly cloudy" };
    try testing.expectEqualStrings("Austin: 72°F, Partly cloudy, wind 12 mph", renderLine(&b, "Austin", r, .imperial));
    try testing.expectEqualStrings("Paris: 22°C, Partly cloudy, wind 20 km/h", renderLine(&b, "Paris", r, .metric));
}

test "renderLine omits an empty description" {
    var b: [128]u8 = undefined;
    const r = Reading{ .temp_c = 10.0, .wind_kph = 0 };
    try testing.expectEqualStrings("Oslo: 10°C, wind 0 km/h", renderLine(&b, "Oslo", r, .metric));
}

test "resolveSystem honors override then country" {
    try testing.expectEqual(UnitSystem.imperial, resolveSystem("imperial", "FR"));
    try testing.expectEqual(UnitSystem.metric, resolveSystem("metric", "US"));
    try testing.expectEqual(UnitSystem.uk, resolveSystem("UK", "US"));
    try testing.expectEqual(UnitSystem.imperial, resolveSystem("auto", "US"));
    try testing.expectEqual(UnitSystem.metric, resolveSystem("", "DE"));
}

test "parseForecast reads key=value source and renders localized" {
    const src =
        \\# sample source written by an external updater
        \\location=Austin
        \\country=US
        \\temp_c=22.0
        \\wind_kph=20
        \\desc=Partly cloudy
        \\
    ;
    const f = parseForecast(src);
    try testing.expectEqualStrings("Austin", f.location);
    try testing.expectEqualStrings("US", f.country);
    try testing.expectEqualStrings("Partly cloudy", f.reading.desc);
    try testing.expectEqual(@as(f64, 22.0), f.reading.temp_c);

    var b: [128]u8 = undefined;
    const sys = resolveSystem("auto", f.country);
    try testing.expectEqualStrings("Austin: 72°F, Partly cloudy, wind 12 mph", renderLine(&b, f.location, f.reading, sys));
}
