// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure, allocation-free URL parser for a practical subset of RFC 3986.
//!
//! Targets the URL shapes the daemon actually handles: `http`, `https`,
//! `ircs`, and `irc` URLs as they appear in fields such as a VHOST URL or in
//! link handling. The parser performs zero allocations and returns slices that
//! borrow directly into the caller-provided input, so the returned `Url` is
//! valid only for as long as `raw` is alive.
//!
//! Grammar handled (informal, hierarchical subset of RFC 3986):
//!
//!     URL       = scheme "://" authority path [ "?" query ] [ "#" fragment ]
//!     authority = [ userinfo "@" ] host [ ":" port ]
//!     host      = reg-name / IPv4address / "[" IPv6address "]"
//!
//! Notable simplifications: percent-encoding is accepted syntactically but not
//! decoded, the authority component is required (the "//" form), and the host
//! charset is validated permissively rather than against the full RFC ABNF.

const std = @import("std");

/// Maximum accepted length of an input URL, in bytes.
///
/// Bounds work performed by the parser and protects callers that forward
/// untrusted input. Chosen to comfortably exceed any realistic IRC/VHOST URL.
pub const max_url_len: usize = 2048;

/// Errors produced while parsing a URL.
pub const ParseError = error{
    /// Input did not contain a `scheme://` prefix.
    NoScheme,
    /// Scheme was empty or contained characters outside the allowed charset.
    BadScheme,
    /// Host component was empty or malformed (bad reg-name / IPv4 / IPv6).
    BadHost,
    /// Port was non-numeric, empty, or greater than 65535.
    BadPort,
    /// Input exceeded `max_url_len`.
    TooLong,
};

/// A parsed URL whose component slices borrow into the original `raw` input.
///
/// Empty optional textual components are represented as empty slices, except
/// `port`, which is `null` when absent. `userinfo` is an empty slice when the
/// authority carried no `user[:pass]@` segment.
pub const Url = struct {
    /// Scheme in its original case (e.g. `https`, `irc`). Never empty.
    scheme: []const u8,
    /// Userinfo without the trailing `@` (e.g. `user:pass`). Empty when absent.
    userinfo: []const u8,
    /// Host as reg-name, IPv4 literal, or bracketless IPv6 literal. Never empty.
    ///
    /// For bracketed IPv6 input the surrounding `[` and `]` are stripped.
    host: []const u8,
    /// Parsed port, or `null` when the authority carried no `:port`.
    port: ?u16,
    /// Path including its leading `/`, or empty when no path was present.
    path: []const u8,
    /// Query string without the leading `?`. Empty when absent.
    query: []const u8,
    /// Fragment without the leading `#`. Empty when absent.
    fragment: []const u8,

    /// Returns true: a successfully parsed `Url` always has a scheme and is
    /// therefore an absolute URI reference.
    pub fn isAbsolute(self: Url) bool {
        return self.scheme.len > 0;
    }

    /// Returns the effective port: the explicit `port` when present, otherwise
    /// the well-known default for the scheme, or `null` if neither is known.
    pub fn effectivePort(self: Url) ?u16 {
        return self.port orelse defaultPort(self.scheme);
    }
};

/// Returns the default port for a known scheme, or `null` for unknown schemes.
///
/// Scheme comparison is case-insensitive per RFC 3986 section 3.1.
pub fn defaultPort(scheme: []const u8) ?u16 {
    const Entry = struct { name: []const u8, port: u16 };
    const table = [_]Entry{
        .{ .name = "http", .port = 80 },
        .{ .name = "https", .port = 443 },
        .{ .name = "irc", .port = 6667 },
        .{ .name = "ircs", .port = 6697 },
        .{ .name = "ws", .port = 80 },
        .{ .name = "wss", .port = 443 },
    };
    for (table) |entry| {
        if (std.ascii.eqlIgnoreCase(scheme, entry.name)) return entry.port;
    }
    return null;
}

/// Reports whether `c` is valid within a URL scheme after the first character.
///
/// Per RFC 3986: `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
fn isSchemeTailChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '+' or c == '-' or c == '.';
}

/// Reports whether `c` is acceptable inside a reg-name host.
///
/// Permissive superset of the RFC `reg-name` production: unreserved characters,
/// sub-delims, and `%` for percent-encoding. Excludes authority delimiters.
fn isRegNameChar(c: u8) bool {
    if (std.ascii.isAlphanumeric(c)) return true;
    return switch (c) {
        '-', '.', '_', '~' => true, // unreserved
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => true, // sub-delims
        '%' => true, // pct-encoded marker
        else => false,
    };
}

/// Reports whether `c` is acceptable inside a bracketed IPv6 host literal.
///
/// Covers hex digits, the `:` separator, and `.` for IPv4-in-IPv6 tails. This
/// is a charset gate, not a full IPv6 grammar validation.
fn isIpv6Char(c: u8) bool {
    return std.ascii.isHex(c) or c == ':' or c == '.';
}

/// Reports whether `c` is acceptable inside userinfo.
///
/// Allows unreserved, sub-delims, `%`, and `:` (user:password separator).
fn isUserinfoChar(c: u8) bool {
    return isRegNameChar(c) or c == ':';
}

/// Validates a scheme slice and returns it unchanged, or `error.BadScheme`.
fn validateScheme(scheme: []const u8) ParseError![]const u8 {
    if (scheme.len == 0) return error.BadScheme;
    if (!std.ascii.isAlphabetic(scheme[0])) return error.BadScheme;
    for (scheme[1..]) |c| {
        if (!isSchemeTailChar(c)) return error.BadScheme;
    }
    return scheme;
}

/// Validates a host slice (reg-name, IPv4 literal, or bracketless IPv6).
///
/// `is_v6` selects the IPv6 charset gate used for bracketed literals whose
/// brackets the caller has already stripped.
fn validateHost(host: []const u8, is_v6: bool) ParseError![]const u8 {
    if (host.len == 0) return error.BadHost;
    if (is_v6) {
        for (host) |c| {
            if (!isIpv6Char(c)) return error.BadHost;
        }
        // Require at least one separator so a bracketed literal is plausibly v6.
        if (std.mem.indexOfScalar(u8, host, ':') == null) return error.BadHost;
        return host;
    }
    for (host) |c| {
        if (!isRegNameChar(c)) return error.BadHost;
    }
    return host;
}

/// Parses and validates a non-empty numeric port string into a `u16`.
fn parsePort(text: []const u8) ParseError!u16 {
    if (text.len == 0) return error.BadPort;
    var value: u32 = 0;
    for (text) |c| {
        if (!std.ascii.isDigit(c)) return error.BadPort;
        value = value * 10 + (c - '0');
        if (value > std.math.maxInt(u16)) return error.BadPort;
    }
    return @intCast(value);
}

/// Splits an authority component into userinfo, host, and optional port.
///
/// `authority` must not include the leading `//`. Brackets around an IPv6 host
/// are stripped; a `:port` after a bracketed host is parsed only when it sits
/// immediately after the closing `]`.
fn parseAuthority(authority: []const u8) ParseError!struct {
    userinfo: []const u8,
    host: []const u8,
    port: ?u16,
} {
    if (authority.len == 0) return error.BadHost;

    var rest = authority;
    var userinfo: []const u8 = authority[0..0];

    // Userinfo ends at the last '@' so '@' may legitimately appear in a
    // password only when percent-encoded; we accept the simple last-'@' rule.
    if (std.mem.lastIndexOfScalar(u8, rest, '@')) |at| {
        userinfo = rest[0..at];
        for (userinfo) |c| {
            if (!isUserinfoChar(c)) return error.BadHost;
        }
        rest = rest[at + 1 ..];
    }

    if (rest.len == 0) return error.BadHost;

    var host: []const u8 = undefined;
    var port: ?u16 = null;

    if (rest[0] == '[') {
        const close = std.mem.indexOfScalar(u8, rest, ']') orelse return error.BadHost;
        host = try validateHost(rest[1..close], true);
        const after = rest[close + 1 ..];
        if (after.len > 0) {
            if (after[0] != ':') return error.BadHost;
            port = try parsePort(after[1..]);
        }
    } else if (std.mem.lastIndexOfScalar(u8, rest, ':')) |colon| {
        host = try validateHost(rest[0..colon], false);
        port = try parsePort(rest[colon + 1 ..]);
    } else {
        host = try validateHost(rest, false);
    }

    return .{ .userinfo = userinfo, .host = host, .port = port };
}

/// Parses `raw` into a `Url`, returning borrowed slices into `raw`.
///
/// The authority (`//host`) form is required. Path, query, and fragment are
/// optional and split on the first `?` and first `#` after the authority.
pub fn parse(raw: []const u8) ParseError!Url {
    if (raw.len > max_url_len) return error.TooLong;

    const scheme_sep = std.mem.indexOf(u8, raw, "://") orelse return error.NoScheme;
    const scheme = try validateScheme(raw[0..scheme_sep]);

    var rest = raw[scheme_sep + 3 ..];

    // The authority runs until the first path/query/fragment delimiter.
    var authority_end: usize = rest.len;
    for (rest, 0..) |c, i| {
        if (c == '/' or c == '?' or c == '#') {
            authority_end = i;
            break;
        }
    }

    const authority = rest[0..authority_end];
    const parts = try parseAuthority(authority);

    var tail = rest[authority_end..];

    // Fragment is everything after the first '#'.
    var fragment: []const u8 = tail[tail.len..];
    if (std.mem.indexOfScalar(u8, tail, '#')) |hash| {
        fragment = tail[hash + 1 ..];
        tail = tail[0..hash];
    }

    // Query is everything after the first '?' (within the non-fragment tail).
    var query: []const u8 = tail[tail.len..];
    if (std.mem.indexOfScalar(u8, tail, '?')) |q| {
        query = tail[q + 1 ..];
        tail = tail[0..q];
    }

    // Whatever remains is the path (may be empty, includes any leading '/').
    const path = tail;

    return Url{
        .scheme = scheme,
        .userinfo = parts.userinfo,
        .host = parts.host,
        .port = parts.port,
        .path = path,
        .query = query,
        .fragment = fragment,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parse full https URL with all components" {
    const u = try parse("https://user:pass@example.com:8443/a/b?x=1&y=2#frag");
    try testing.expectEqualStrings("https", u.scheme);
    try testing.expectEqualStrings("user:pass", u.userinfo);
    try testing.expectEqualStrings("example.com", u.host);
    try testing.expectEqual(@as(?u16, 8443), u.port);
    try testing.expectEqualStrings("/a/b", u.path);
    try testing.expectEqualStrings("x=1&y=2", u.query);
    try testing.expectEqualStrings("frag", u.fragment);
    try testing.expect(u.isAbsolute());
}

test "parse scheme and host only" {
    const u = try parse("http://example.org");
    try testing.expectEqualStrings("http", u.scheme);
    try testing.expectEqualStrings("", u.userinfo);
    try testing.expectEqualStrings("example.org", u.host);
    try testing.expectEqual(@as(?u16, null), u.port);
    try testing.expectEqualStrings("", u.path);
    try testing.expectEqualStrings("", u.query);
    try testing.expectEqualStrings("", u.fragment);
}

test "parse explicit port" {
    const u = try parse("ircs://irc.example.net:6697");
    try testing.expectEqualStrings("ircs", u.scheme);
    try testing.expectEqualStrings("irc.example.net", u.host);
    try testing.expectEqual(@as(?u16, 6697), u.port);
}

test "parse bracketed IPv6 host without port" {
    const u = try parse("https://[2001:db8::1]/path");
    try testing.expectEqualStrings("2001:db8::1", u.host);
    try testing.expectEqual(@as(?u16, null), u.port);
    try testing.expectEqualStrings("/path", u.path);
}

test "parse bracketed IPv6 host with port" {
    const u = try parse("https://[::1]:9000/");
    try testing.expectEqualStrings("::1", u.host);
    try testing.expectEqual(@as(?u16, 9000), u.port);
    try testing.expectEqualStrings("/", u.path);
}

test "parse IPv4 literal host" {
    const u = try parse("irc://192.0.2.10:6667/#chan");
    try testing.expectEqualStrings("192.0.2.10", u.host);
    try testing.expectEqual(@as(?u16, 6667), u.port);
    try testing.expectEqualStrings("/", u.path);
    try testing.expectEqualStrings("chan", u.fragment);
}

test "parse query without fragment" {
    const u = try parse("https://example.com/search?q=zig");
    try testing.expectEqualStrings("/search", u.path);
    try testing.expectEqualStrings("q=zig", u.query);
    try testing.expectEqualStrings("", u.fragment);
}

test "parse fragment without query" {
    const u = try parse("https://example.com/doc#section");
    try testing.expectEqualStrings("/doc", u.path);
    try testing.expectEqualStrings("", u.query);
    try testing.expectEqualStrings("section", u.fragment);
}

test "parse fragment containing question mark stays in fragment" {
    const u = try parse("https://example.com/p#a?b");
    try testing.expectEqualStrings("/p", u.path);
    try testing.expectEqualStrings("", u.query);
    try testing.expectEqualStrings("a?b", u.fragment);
}

test "parse userinfo without password" {
    const u = try parse("irc://nick@irc.example.net/");
    try testing.expectEqualStrings("nick", u.userinfo);
    try testing.expectEqualStrings("irc.example.net", u.host);
}

test "parse empty query and fragment markers" {
    const u = try parse("https://h.example/?#");
    try testing.expectEqualStrings("/", u.path);
    try testing.expectEqualStrings("", u.query);
    try testing.expectEqualStrings("", u.fragment);
}

test "scheme comparison and defaults are case-insensitive" {
    const u = try parse("HTTPS://Example.COM/");
    try testing.expectEqualStrings("HTTPS", u.scheme);
    try testing.expectEqual(@as(?u16, 443), u.effectivePort());
}

test "effectivePort prefers explicit port over default" {
    const u = try parse("http://example.com:8080/");
    try testing.expectEqual(@as(?u16, 8080), u.effectivePort());
}

test "effectivePort falls back to scheme default" {
    const u = try parse("irc://irc.example.net/");
    try testing.expectEqual(@as(?u16, 6667), u.effectivePort());
}

test "defaultPort known and unknown schemes" {
    try testing.expectEqual(@as(?u16, 80), defaultPort("http"));
    try testing.expectEqual(@as(?u16, 443), defaultPort("https"));
    try testing.expectEqual(@as(?u16, 6667), defaultPort("irc"));
    try testing.expectEqual(@as(?u16, 6697), defaultPort("ircs"));
    try testing.expectEqual(@as(?u16, 80), defaultPort("ws"));
    try testing.expectEqual(@as(?u16, 443), defaultPort("wss"));
    try testing.expectEqual(@as(?u16, null), defaultPort("gopher"));
}

test "borrowed slices point into the original input" {
    const raw = "https://example.com:1234/p?q#f";
    const u = try parse(raw);
    // host slice must be a subslice of raw (same backing memory).
    const host_off = @intFromPtr(u.host.ptr) - @intFromPtr(raw.ptr);
    try testing.expect(host_off < raw.len);
    try testing.expectEqualStrings("example.com", raw[host_off .. host_off + u.host.len]);
}

test "error: missing scheme separator" {
    try testing.expectError(error.NoScheme, parse("example.com/path"));
}

test "error: empty scheme" {
    try testing.expectError(error.BadScheme, parse("://example.com"));
}

test "error: scheme starting with digit" {
    try testing.expectError(error.BadScheme, parse("1http://example.com"));
}

test "error: scheme with illegal character" {
    try testing.expectError(error.BadScheme, parse("ht tp://example.com"));
}

test "error: empty host" {
    try testing.expectError(error.BadHost, parse("https:///path"));
}

test "error: empty host before port" {
    try testing.expectError(error.BadHost, parse("https://:8080/"));
}

test "error: illegal character in host" {
    try testing.expectError(error.BadHost, parse("https://exa mple.com/"));
}

test "error: unterminated IPv6 bracket" {
    try testing.expectError(error.BadHost, parse("https://[2001:db8::1/path"));
}

test "error: bracketed host without colon is not IPv6" {
    try testing.expectError(error.BadHost, parse("https://[abcd]/"));
}

test "error: junk between IPv6 bracket and port" {
    try testing.expectError(error.BadHost, parse("https://[::1]x/"));
}

test "error: non-numeric port" {
    try testing.expectError(error.BadPort, parse("https://example.com:80a/"));
}

test "error: empty port" {
    try testing.expectError(error.BadPort, parse("https://example.com:/"));
}

test "error: port out of range" {
    try testing.expectError(error.BadPort, parse("https://example.com:65536/"));
}

test "port at the u16 boundary is accepted" {
    const u = try parse("https://example.com:65535/");
    try testing.expectEqual(@as(?u16, 65535), u.port);
}

test "error: input exceeding max length" {
    var buf: [max_url_len + 16]u8 = undefined;
    const prefix = "https://example.com/";
    @memcpy(buf[0..prefix.len], prefix);
    @memset(buf[prefix.len..], 'a');
    try testing.expectError(error.TooLong, parse(buf[0..]));
}

test "input at exactly max length is allowed" {
    var buf: [max_url_len]u8 = undefined;
    const prefix = "https://example.com/";
    @memcpy(buf[0..prefix.len], prefix);
    @memset(buf[prefix.len..], 'a');
    const u = try parse(buf[0..]);
    try testing.expectEqualStrings("example.com", u.host);
}

test "userinfo with multiple @ uses the last as delimiter" {
    const u = try parse("https://a%40b@host.example/");
    try testing.expectEqualStrings("a%40b", u.userinfo);
    try testing.expectEqualStrings("host.example", u.host);
}

test "host-only authority with trailing query" {
    const u = try parse("https://example.com?q=1");
    try testing.expectEqualStrings("example.com", u.host);
    try testing.expectEqualStrings("", u.path);
    try testing.expectEqualStrings("q=1", u.query);
}
