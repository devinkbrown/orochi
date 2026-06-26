// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! DNS blocklist (DNSBL) name-building and answer classification.
//!
//! This module is pure and I/O-free. It composes the reversed-address query
//! name for a blocklist zone and classifies the A-record answers a resolver
//! returns. The actual UDP lookup lives in the daemon's resolver and is not
//! part of this module.

const std = @import("std");

/// Maximum length of a DNS name in bytes, excluding the trailing root label.
const max_name_len: usize = 253;

/// Errors returned while composing query names.
pub const Error = error{
    /// The composed query name would not fit in `out` or exceeds the DNS name
    /// length limit (253 bytes).
    NameTooLong,
    /// The supplied address or zone is invalid.
    InvalidAddress,
};

/// Builds the reversed-IPv4 query name for `zone` into `out`.
///
/// For ip `{1, 2, 3, 4}` and zone `"zen.example.org"` the result is
/// `"4.3.2.1.zen.example.org"`. Returns a slice of `out`. `out` must hold at
/// least `16 + zone.len` bytes (4 octets up to "255." each); too small yields
/// `NameTooLong`, as does a composed name exceeding the 253-byte DNS limit.
pub fn reverseNameV4(ip: [4]u8, zone: []const u8, out: []u8) Error![]const u8 {
    if (zone.len == 0) return Error.InvalidAddress;
    var cursor: Cursor = .{ .out = out };
    var i: usize = ip.len;
    while (i > 0) : (i -= 1) {
        try cursor.decimal(ip[i - 1]);
        try cursor.byte('.');
    }
    try cursor.slice(zone);
    return cursor.finish();
}

/// Builds the nibble-reversed IPv6 query name for `zone` into `out`.
///
/// Each of the 32 nibbles is emitted least-significant-first as lowercase hex,
/// dot-separated, followed by `zone`. Returns a slice of `out`. `out` must hold
/// at least `64 + zone.len` bytes (32 nibbles + 32 dots); too small yields
/// `NameTooLong`, as does a composed name exceeding the 253-byte DNS limit.
pub fn reverseNameV6(ip: [16]u8, zone: []const u8, out: []u8) Error![]const u8 {
    if (zone.len == 0) return Error.InvalidAddress;
    var cursor: Cursor = .{ .out = out };
    var i: usize = ip.len;
    while (i > 0) : (i -= 1) {
        const octet = ip[i - 1];
        try cursor.byte(nibbleHex(octet & 0x0f));
        try cursor.byte('.');
        try cursor.byte(nibbleHex(octet >> 4));
        try cursor.byte('.');
    }
    try cursor.slice(zone);
    return cursor.finish();
}

/// Result of classifying the A-record answers from a blocklist lookup.
pub const Listing = struct {
    /// True when at least one answer falls inside 127.0.0.0/8.
    listed: bool,
    /// Last octet of the first listing answer; the blocklist return code.
    code: u8,
};

/// Classifies blocklist A-record answers into a `Listing`.
///
/// DNSBLs reply with addresses in 127.0.0.0/8 whose final octet encodes the
/// listing reason. Non-127 answers are ignored; an empty answer set (NXDOMAIN)
/// is reported as not listed with code `0`.
pub fn classify(a_records: []const [4]u8) Listing {
    for (a_records) |record| {
        if (record[0] == 127) {
            return .{ .listed = true, .code = record[3] };
        }
    }
    return .{ .listed = false, .code = 0 };
}

/// A single blocklist zone. The `host` slice is borrowed; no ownership.
pub const Zone = struct {
    host: []const u8,
};

/// Runtime blocklist configuration. Zones are borrowed and populated by the
/// caller; the daemon owns the backing storage.
pub const Config = struct {
    zones: []const Zone,
    enabled: bool = false,
};

/// Append-only cursor over a borrowed output buffer. Tracks position and maps
/// overflow to `NameTooLong`; `finish` enforces the DNS name length limit.
const Cursor = struct {
    out: []u8,
    len: usize = 0,

    fn byte(self: *Cursor, value: u8) Error!void {
        if (self.len >= self.out.len) return Error.NameTooLong;
        self.out[self.len] = value;
        self.len += 1;
    }

    fn decimal(self: *Cursor, value: u8) Error!void {
        var digits: [3]u8 = undefined;
        const text = std.fmt.bufPrint(&digits, "{d}", .{value}) catch unreachable;
        try self.slice(text);
    }

    fn slice(self: *Cursor, bytes: []const u8) Error!void {
        if (self.len + bytes.len > self.out.len) return Error.NameTooLong;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn finish(self: *const Cursor) Error![]const u8 {
        if (self.len > max_name_len) return Error.NameTooLong;
        return self.out[0..self.len];
    }
};

/// Returns the lowercase hex digit for the low nibble of `value`.
fn nibbleHex(value: u8) u8 {
    return "0123456789abcdef"[value & 0x0f];
}

test "reverseNameV4 reverses octets before the zone" {
    var buf: [64]u8 = undefined;
    const name = try reverseNameV4(.{ 1, 2, 3, 4 }, "zen.example.org", &buf);
    try std.testing.expectEqualStrings("4.3.2.1.zen.example.org", name);
}

test "reverseNameV6 nibble-reverses the address" {
    // 2001:db8::1 expands to 20 01 0d b8 00..00 00 01.
    const ip = [16]u8{
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    var buf: [128]u8 = undefined;
    const name = try reverseNameV6(ip, "dnsbl.example.net", &buf);
    const expected = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.dnsbl.example.net";
    try std.testing.expectEqualStrings(expected, name);
}

test "classify reports a 127.0.0.x answer as listed" {
    const listing = classify(&.{.{ 127, 0, 0, 2 }});
    try std.testing.expectEqual(Listing{ .listed = true, .code = 2 }, listing);
}

test "classify treats no answers as not listed" {
    const listing = classify(&.{});
    try std.testing.expectEqual(Listing{ .listed = false, .code = 0 }, listing);
}

test "classify ignores non-127 answers" {
    const listing = classify(&.{.{ 8, 8, 8, 8 }});
    try std.testing.expectEqual(Listing{ .listed = false, .code = 0 }, listing);
}

test "reverseNameV4 rejects an undersized output buffer" {
    var buf: [4]u8 = undefined;
    try std.testing.expectError(Error.NameTooLong, reverseNameV4(.{ 1, 2, 3, 4 }, "zen.example.org", &buf));
}
