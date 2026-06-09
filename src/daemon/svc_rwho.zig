//! Pure RWHO/wide-WHO filter parsing and matching.
//!
//! This module intentionally owns no client store and emits no pseudo-client
//! service rows. Callers should use real server commands and normal WHO
//! numerics when wiring the filtered result set.
const std = @import("std");

pub const command_name = "RWHO";

pub const Numeric = enum(u16) {
    RPL_ENDOFWHO = 315,
    RPL_WHOREPLY = 352,
};

pub const ParseError = error{
    DuplicateField,
    EmptyToken,
    InvalidValue,
    MissingValue,
    UnknownToken,
};

pub const Filter = struct {
    account: ?[]const u8 = null,
    ip_glob: ?[]const u8 = null,
    host_glob: ?[]const u8 = null,
    oper_only: bool = false,
    away_only: bool = false,
    realname_glob: ?[]const u8 = null,

    pub fn isEmpty(self: Filter) bool {
        return self.account == null and
            self.ip_glob == null and
            self.host_glob == null and
            !self.oper_only and
            !self.away_only and
            self.realname_glob == null;
    }
};

pub const ClientFacts = struct {
    account: ?[]const u8 = null,
    ip: []const u8 = "",
    host: []const u8 = "",
    oper: bool = false,
    away: bool = false,
    realname: []const u8 = "",
};

pub fn parseSpec(spec: []const u8) ParseError!Filter {
    var filter = Filter{};
    var cursor: usize = 0;

    while (cursor < spec.len) {
        while (cursor < spec.len and isSeparator(spec[cursor])) : (cursor += 1) {}
        if (cursor >= spec.len) break;

        const start = cursor;
        while (cursor < spec.len and !isSeparator(spec[cursor])) : (cursor += 1) {}
        try parseToken(spec[start..cursor], &filter);
    }

    return filter;
}

pub fn matches(filter: Filter, facts: ClientFacts) bool {
    if (filter.oper_only and !facts.oper) return false;
    if (filter.away_only and !facts.away) return false;

    if (filter.account) |account| {
        const actual = facts.account orelse return false;
        if (!std.ascii.eqlIgnoreCase(account, actual)) return false;
    }

    if (filter.ip_glob) |pattern| {
        if (!globMatch(pattern, facts.ip)) return false;
    }

    if (filter.host_glob) |pattern| {
        if (!globMatch(pattern, facts.host)) return false;
    }

    if (filter.realname_glob) |pattern| {
        if (!globMatch(pattern, facts.realname)) return false;
    }

    return true;
}

pub fn globMatch(pattern: []const u8, text: []const u8) bool {
    var pattern_index: usize = 0;
    var text_index: usize = 0;
    var star_index: ?usize = null;
    var retry_text_index: usize = 0;

    while (text_index < text.len) {
        if (pattern_index < pattern.len and
            (pattern[pattern_index] == '?' or sameFolded(pattern[pattern_index], text[text_index])))
        {
            pattern_index += 1;
            text_index += 1;
        } else if (pattern_index < pattern.len and pattern[pattern_index] == '*') {
            star_index = pattern_index;
            pattern_index += 1;
            retry_text_index = text_index;
        } else if (star_index) |star| {
            pattern_index = star + 1;
            retry_text_index += 1;
            text_index = retry_text_index;
        } else {
            return false;
        }
    }

    while (pattern_index < pattern.len and pattern[pattern_index] == '*') : (pattern_index += 1) {}
    return pattern_index == pattern.len;
}

fn parseToken(token: []const u8, filter: *Filter) ParseError!void {
    if (token.len == 0) return error.EmptyToken;

    if (std.ascii.eqlIgnoreCase(token, "oper-only")) {
        if (filter.oper_only) return error.DuplicateField;
        filter.oper_only = true;
        return;
    }

    if (std.ascii.eqlIgnoreCase(token, "away-only")) {
        if (filter.away_only) return error.DuplicateField;
        filter.away_only = true;
        return;
    }

    const equals = std.mem.indexOfScalar(u8, token, '=') orelse return error.UnknownToken;
    const key = token[0..equals];
    const value = token[equals + 1 ..];
    if (key.len == 0) return error.UnknownToken;
    try validateValue(value);

    if (std.ascii.eqlIgnoreCase(key, "account")) {
        if (filter.account != null) return error.DuplicateField;
        filter.account = value;
    } else if (std.ascii.eqlIgnoreCase(key, "ip-glob")) {
        if (filter.ip_glob != null) return error.DuplicateField;
        filter.ip_glob = value;
    } else if (std.ascii.eqlIgnoreCase(key, "host-glob")) {
        if (filter.host_glob != null) return error.DuplicateField;
        filter.host_glob = value;
    } else if (std.ascii.eqlIgnoreCase(key, "realname-glob")) {
        if (filter.realname_glob != null) return error.DuplicateField;
        filter.realname_glob = value;
    } else {
        return error.UnknownToken;
    }
}

fn validateValue(value: []const u8) ParseError!void {
    if (value.len == 0) return error.MissingValue;
    for (value) |byte| {
        switch (byte) {
            0, '\r', '\n' => return error.InvalidValue,
            else => {},
        }
    }
}

fn isSeparator(byte: u8) bool {
    return switch (byte) {
        ',', ' ', '\t', '\r', '\n' => true,
        else => false,
    };
}

fn sameFolded(a: u8, b: u8) bool {
    return std.ascii.toLower(a) == std.ascii.toLower(b);
}

fn sampleFacts() ClientFacts {
    return .{
        .account = "alice",
        .ip = "203.0.113.42",
        .host = "gateway.users.example",
        .oper = true,
        .away = true,
        .realname = "Alice Example",
    };
}

test "public command and numerics are server WHO surfaces" {
    try std.testing.expectEqualStrings("RWHO", command_name);
    try std.testing.expectEqual(@as(u16, 352), @intFromEnum(Numeric.RPL_WHOREPLY));
    try std.testing.expectEqual(@as(u16, 315), @intFromEnum(Numeric.RPL_ENDOFWHO));
}

test "empty spec parses to match-all filter" {
    const filter = try parseSpec(" \t,\n ");
    try std.testing.expect(filter.isEmpty());
    try std.testing.expect(matches(filter, .{}));
    try std.testing.expect(matches(filter, sampleFacts()));
}

test "parse all filter facets from mixed separators" {
    const filter = try parseSpec("account=alice,ip-glob=203.0.113.*,host-glob=*.example oper-only away-only realname-glob=Alice*");

    try std.testing.expectEqualStrings("alice", filter.account.?);
    try std.testing.expectEqualStrings("203.0.113.*", filter.ip_glob.?);
    try std.testing.expectEqualStrings("*.example", filter.host_glob.?);
    try std.testing.expect(filter.oper_only);
    try std.testing.expect(filter.away_only);
    try std.testing.expectEqualStrings("Alice*", filter.realname_glob.?);
}

test "parser accepts case-insensitive keys and flags" {
    const filter = try parseSpec("ACCOUNT=ALICE IP-GLOB=203.* HOST-GLOB=*.EXAMPLE OPER-ONLY AWAY-ONLY REALNAME-GLOB=*EXAMPLE");

    try std.testing.expect(matches(filter, sampleFacts()));
}

test "parser rejects unknown tokens and missing values" {
    try std.testing.expectError(error.UnknownToken, parseSpec("nick-glob=alice"));
    try std.testing.expectError(error.UnknownToken, parseSpec("oper-only=true"));
    try std.testing.expectError(error.MissingValue, parseSpec("account="));
    try std.testing.expectError(error.MissingValue, parseSpec("host-glob="));
    try std.testing.expectError(error.InvalidValue, parseSpec("account=bad\x00value"));
}

test "parser rejects duplicate fields and flags" {
    try std.testing.expectError(error.DuplicateField, parseSpec("account=alice account=bob"));
    try std.testing.expectError(error.DuplicateField, parseSpec("ip-glob=203.* ip-glob=198.*"));
    try std.testing.expectError(error.DuplicateField, parseSpec("host-glob=*.a host-glob=*.b"));
    try std.testing.expectError(error.DuplicateField, parseSpec("realname-glob=A* realname-glob=B*"));
    try std.testing.expectError(error.DuplicateField, parseSpec("oper-only oper-only"));
    try std.testing.expectError(error.DuplicateField, parseSpec("away-only away-only"));
}

test "account filter requires logged-in account and folds ascii case" {
    const filter = try parseSpec("account=ALICE");

    try std.testing.expect(matches(filter, sampleFacts()));
    try std.testing.expect(!matches(filter, .{ .account = "bob" }));
    try std.testing.expect(!matches(filter, .{ .account = null }));
}

test "ip glob filter matches addresses case-insensitively" {
    const filter = try parseSpec("ip-glob=2001:DB8:*");

    try std.testing.expect(matches(filter, .{ .ip = "2001:db8::1" }));
    try std.testing.expect(matches(try parseSpec("ip-glob=203.0.113.?2"), sampleFacts()));
    try std.testing.expect(!matches(filter, .{ .ip = "2001:db9::1" }));
}

test "host glob filter covers prefix suffix and question wildcard" {
    const filter = try parseSpec("host-glob=gateway.users.examp?e");

    try std.testing.expect(matches(filter, sampleFacts()));
    try std.testing.expect(matches(try parseSpec("host-glob=*.USERS.EXAMPLE"), sampleFacts()));
    try std.testing.expect(!matches(filter, .{ .host = "gateway.users.invalid" }));
}

test "oper-only and away-only require their respective booleans" {
    const filter = try parseSpec("oper-only away-only");

    try std.testing.expect(matches(filter, sampleFacts()));
    try std.testing.expect(!matches(filter, .{ .oper = false, .away = true }));
    try std.testing.expect(!matches(filter, .{ .oper = true, .away = false }));
}

test "realname glob matches real client facts only" {
    const filter = try parseSpec("realname-glob=*Example");

    try std.testing.expect(matches(filter, sampleFacts()));
    try std.testing.expect(matches(try parseSpec("realname-glob=ALICE*"), sampleFacts()));
    try std.testing.expect(!matches(filter, .{ .realname = "Alice Other" }));
}

test "combined filter short-circuits on any mismatched facet" {
    const filter = try parseSpec("account=alice ip-glob=203.0.113.* host-glob=*.example oper-only away-only realname-glob=Alice*");

    try std.testing.expect(matches(filter, sampleFacts()));
    try std.testing.expect(!matches(filter, .{ .account = "alice", .ip = "198.51.100.7", .host = "gateway.users.example", .oper = true, .away = true, .realname = "Alice Example" }));
    try std.testing.expect(!matches(filter, .{ .account = "alice", .ip = "203.0.113.42", .host = "gateway.users.invalid", .oper = true, .away = true, .realname = "Alice Example" }));
    try std.testing.expect(!matches(filter, .{ .account = "alice", .ip = "203.0.113.42", .host = "gateway.users.example", .oper = true, .away = true, .realname = "Bob Example" }));
}

test "glob matcher handles star question and empty text edges" {
    try std.testing.expect(globMatch("*", ""));
    try std.testing.expect(globMatch("", ""));
    try std.testing.expect(globMatch("a*e", "alice"));
    try std.testing.expect(globMatch("a*c?", "aBBBce"));
    try std.testing.expect(globMatch("?lice", "Alice"));

    try std.testing.expect(!globMatch("", "alice"));
    try std.testing.expect(!globMatch("ali?", "alice"));
    try std.testing.expect(!globMatch("bob*", "alice"));
}
