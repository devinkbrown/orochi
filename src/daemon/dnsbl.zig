//! DNS blocklist policy helpers.
//!
//! This module performs no DNS I/O. It builds IPv4 DNSBL query names and
//! interprets DNS A answers supplied by the caller.
const std = @import("std");

/// Policy action selected when a DNS blocklist zone matches.
pub const Action = enum {
    none,
    warn,
    refuse,
    require_auth,
};

/// DNS blocklist lookup verdict.
pub const Verdict = enum {
    clean,
    listed,
};

/// DNS blocklist zone policy.
pub const Zone = struct {
    suffix: []const u8,
    action: Action,
    weight: u8,
    reason: []const u8,
};

/// Runtime limits and DNSBL answer mask.
pub const Params = struct {
    max_zones: usize = 64,
    max_suffix_bytes: usize = 255,
    listed_address: u32 = 0x7f000000,
    listed_mask: u32 = 0xff000000,
};

/// DNS blocklist policy errors.
pub const Error = std.mem.Allocator.Error || error{
    InvalidSuffix,
    SuffixTooLong,
    TooManyZones,
    ZoneExists,
    ZoneNotFound,
    OutputTooSmall,
};

/// Build an IPv4 DNSBL query name into `out`.
///
/// The input IP must be dotted IPv4 text. The output reverses the four octets
/// and appends `zone_suffix`, for example `1.2.3.4` with `dnsbl.example.org`
/// becomes `4.3.2.1.dnsbl.example.org`. Returns null for malformed IPv4,
/// invalid suffixes, or insufficient output space.
pub fn queryName(ip: []const u8, zone_suffix: []const u8, out: []u8) ?[]const u8 {
    const octets = parseIpv4(ip) orelse return null;
    if (!validSuffix(zone_suffix, zone_suffix.len)) return null;

    var len: usize = 0;
    var index: usize = 0;
    while (index < octets.len) : (index += 1) {
        if (index != 0) {
            if (len >= out.len) return null;
            out[len] = '.';
            len += 1;
        }

        const piece = std.fmt.bufPrint(out[len..], "{d}", .{octets[octets.len - 1 - index]}) catch return null;
        len += piece.len;
    }

    if (len >= out.len) return null;
    out[len] = '.';
    len += 1;

    if (out.len - len < zone_suffix.len) return null;
    @memcpy(out[len..][0..zone_suffix.len], zone_suffix);
    len += zone_suffix.len;

    return out[0..len];
}

/// Interpret a DNS A answer using the default DNSBL answer mask.
///
/// The `a_record` value is expected in network-order numeric form, such as
/// `0x7f000002` for `127.0.0.2`. A zero value represents no answer or NXDOMAIN.
pub fn interpret(zone: Zone, a_record: u32) Verdict {
    return interpretWithParams(.{}, zone, a_record);
}

/// Interpret a DNS A answer using an explicit DNSBL answer mask.
///
/// A nonzero answer is listed when `(a_record & listed_mask)` equals
/// `(listed_address & listed_mask)`.
pub fn interpretWithParams(params: Params, zone: Zone, a_record: u32) Verdict {
    _ = zone;
    if (a_record == 0) return .clean;
    if ((a_record & params.listed_mask) == (params.listed_address & params.listed_mask)) return .listed;
    return .clean;
}

/// Owned DNS blocklist zone set.
pub const ZoneList = struct {
    allocator: std.mem.Allocator,
    params: Params,
    zones: std.StringHashMap(StoredZone),

    /// Create a zone list with default limits.
    pub fn init(allocator: std.mem.Allocator) ZoneList {
        return initWithParams(allocator, .{});
    }

    /// Create a zone list with explicit limits.
    pub fn initWithParams(allocator: std.mem.Allocator, params: Params) ZoneList {
        return .{
            .allocator = allocator,
            .params = params,
            .zones = std.StringHashMap(StoredZone).init(allocator),
        };
    }

    /// Free all owned suffix and reason strings.
    pub fn deinit(self: *ZoneList) void {
        var it = self.zones.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.reason);
        }
        self.zones.deinit();
        self.* = undefined;
    }

    /// Add a zone, duplicating its suffix and reason.
    pub fn add(self: *ZoneList, zone: Zone) Error!void {
        try validateSuffixWith(self.params, zone.suffix);
        if (self.zones.contains(zone.suffix)) return error.ZoneExists;
        if (self.zones.count() >= self.params.max_zones) return error.TooManyZones;

        const owned_suffix = try self.allocator.dupe(u8, zone.suffix);
        errdefer self.allocator.free(owned_suffix);
        const owned_reason = try self.allocator.dupe(u8, zone.reason);
        errdefer self.allocator.free(owned_reason);

        try self.zones.putNoClobber(owned_suffix, .{
            .action = zone.action,
            .weight = zone.weight,
            .reason = owned_reason,
        });
    }

    /// Remove a zone by suffix and free its owned strings.
    pub fn remove(self: *ZoneList, zone_suffix: []const u8) Error!void {
        try validateSuffixWith(self.params, zone_suffix);
        const removed = self.zones.fetchRemove(zone_suffix) orelse return error.ZoneNotFound;
        self.allocator.free(removed.key);
        self.allocator.free(removed.value.reason);
    }

    /// Copy borrowed zone views into `out` and return the populated prefix.
    pub fn list(self: *const ZoneList, out: []Zone) Error![]const Zone {
        if (out.len < self.zones.count()) return error.OutputTooSmall;

        var index: usize = 0;
        var it = self.zones.iterator();
        while (it.next()) |entry| {
            out[index] = .{
                .suffix = entry.key_ptr.*,
                .action = entry.value_ptr.action,
                .weight = entry.value_ptr.weight,
                .reason = entry.value_ptr.reason,
            };
            index += 1;
        }
        return out[0..index];
    }

    /// Return the configured action for a suffix.
    pub fn actionFor(self: *const ZoneList, zone_suffix: []const u8) ?Action {
        const zone = self.zones.get(zone_suffix) orelse return null;
        return zone.action;
    }
};

const StoredZone = struct {
    action: Action,
    weight: u8,
    reason: []u8,
};

fn parseIpv4(ip: []const u8) ?[4]u8 {
    if (ip.len == 0) return null;

    var octets: [4]u8 = undefined;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, ip, '.');
    while (it.next()) |part| {
        if (count >= octets.len) return null;
        if (part.len == 0 or part.len > 3) return null;
        octets[count] = std.fmt.parseUnsigned(u8, part, 10) catch return null;
        count += 1;
    }
    if (count != octets.len) return null;
    return octets;
}

fn validateSuffixWith(params: Params, suffix: []const u8) Error!void {
    if (suffix.len > params.max_suffix_bytes) return error.SuffixTooLong;
    if (!validSuffix(suffix, params.max_suffix_bytes)) return error.InvalidSuffix;
}

fn validSuffix(suffix: []const u8, max_suffix_bytes: usize) bool {
    if (suffix.len == 0 or suffix.len > max_suffix_bytes) return false;
    if (suffix[0] == '.' or suffix[suffix.len - 1] == '.') return false;

    var label_len: usize = 0;
    for (suffix) |byte| {
        switch (byte) {
            'a'...'z', 'A'...'Z', '0'...'9', '-' => label_len += 1,
            '.' => {
                if (label_len == 0 or label_len > 63) return false;
                label_len = 0;
            },
            else => return false,
        }
    }
    return label_len > 0 and label_len <= 63;
}

const testing = std.testing;

test "queryName reverses IPv4 octets and appends suffix" {
    // Arrange.
    var out: [64]u8 = undefined;

    // Act.
    const query = queryName("1.2.3.4", "dnsbl.example.org", &out) orelse return error.TestUnexpectedResult;

    // Assert.
    try testing.expectEqualStrings("4.3.2.1.dnsbl.example.org", query);
}

test "queryName returns null for malformed IPv4 input" {
    // Arrange.
    var out: [64]u8 = undefined;

    // Act.
    const too_few_octets = queryName("1.2.3", "dnsbl.example.org", &out);
    const bad_octet = queryName("1.2.3.256", "dnsbl.example.org", &out);
    const empty_octet = queryName("1.2..4", "dnsbl.example.org", &out);

    // Assert.
    try testing.expectEqual(@as(?[]const u8, null), too_few_octets);
    try testing.expectEqual(@as(?[]const u8, null), bad_octet);
    try testing.expectEqual(@as(?[]const u8, null), empty_octet);
}

test "queryName returns null when output buffer is too small" {
    // Arrange.
    var out: [8]u8 = undefined;

    // Act.
    const query = queryName("1.2.3.4", "dnsbl.example.org", &out);

    // Assert.
    try testing.expectEqual(@as(?[]const u8, null), query);
}

test "interpret treats 127.0.0.2 answers as listed" {
    // Arrange.
    const zone = Zone{
        .suffix = "dnsbl.example.org",
        .action = .refuse,
        .weight = 10,
        .reason = "listed",
    };

    // Act.
    const verdict = interpret(zone, 0x7f000002);

    // Assert.
    try testing.expectEqual(Verdict.listed, verdict);
}

test "interpret treats zero answers as clean" {
    // Arrange.
    const zone = Zone{
        .suffix = "dnsbl.example.org",
        .action = .warn,
        .weight = 1,
        .reason = "listed",
    };

    // Act.
    const verdict = interpret(zone, 0);

    // Assert.
    try testing.expectEqual(Verdict.clean, verdict);
}

test "interpretWithParams applies custom answer mask" {
    // Arrange.
    const zone = Zone{
        .suffix = "dnsbl.example.org",
        .action = .warn,
        .weight = 1,
        .reason = "listed",
    };
    const params = Params{
        .listed_address = 0x0a000000,
        .listed_mask = 0xff000000,
    };

    // Act.
    const listed = interpretWithParams(params, zone, 0x0a000002);
    const clean = interpretWithParams(params, zone, 0x7f000002);

    // Assert.
    try testing.expectEqual(Verdict.listed, listed);
    try testing.expectEqual(Verdict.clean, clean);
}

test "ZoneList add list and remove keep owned zones without leaks" {
    // Arrange.
    var zones = ZoneList.init(testing.allocator);
    defer zones.deinit();

    var suffix_buf = [_]u8{ 'd', 'n', 's', 'b', 'l', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'o', 'r', 'g' };
    var reason_buf = [_]u8{ 'l', 'i', 's', 't', 'e', 'd' };
    try zones.add(.{
        .suffix = suffix_buf[0..],
        .action = .refuse,
        .weight = 20,
        .reason = reason_buf[0..],
    });
    @memset(suffix_buf[0..], 'x');
    @memset(reason_buf[0..], 'y');

    // Act.
    var out: [1]Zone = undefined;
    const listed = try zones.list(&out);

    // Assert.
    try testing.expectEqual(@as(usize, 1), listed.len);
    try testing.expectEqualStrings("dnsbl.example.org", listed[0].suffix);
    try testing.expectEqual(Action.refuse, listed[0].action);
    try testing.expectEqual(@as(u8, 20), listed[0].weight);
    try testing.expectEqualStrings("listed", listed[0].reason);

    // Act.
    try zones.remove("dnsbl.example.org");
    const empty = try zones.list(&out);

    // Assert.
    try testing.expectEqual(@as(usize, 0), empty.len);
}

test "ZoneList actionFor returns configured action by suffix" {
    // Arrange.
    var zones = ZoneList.init(testing.allocator);
    defer zones.deinit();
    try zones.add(.{
        .suffix = "dnsbl.example.org",
        .action = .require_auth,
        .weight = 4,
        .reason = "authenticate first",
    });

    // Act.
    const found = zones.actionFor("dnsbl.example.org");
    const missing = zones.actionFor("other.example.org");

    // Assert.
    try testing.expectEqual(Action.require_auth, found.?);
    try testing.expectEqual(@as(?Action, null), missing);
}

test "ZoneList enforces duplicate suffix and zone limit" {
    // Arrange.
    var zones = ZoneList.initWithParams(testing.allocator, .{ .max_zones = 1 });
    defer zones.deinit();

    // Act.
    try zones.add(.{ .suffix = "one.example.org", .action = .warn, .weight = 1, .reason = "first" });
    const duplicate = zones.add(.{ .suffix = "one.example.org", .action = .refuse, .weight = 2, .reason = "duplicate" });
    const overflow = zones.add(.{ .suffix = "two.example.org", .action = .refuse, .weight = 2, .reason = "overflow" });

    // Assert.
    try testing.expectError(error.ZoneExists, duplicate);
    try testing.expectError(error.TooManyZones, overflow);
}

test "ZoneList validates suffix bounds" {
    // Arrange.
    var zones = ZoneList.initWithParams(testing.allocator, .{ .max_suffix_bytes = 8 });
    defer zones.deinit();

    // Act.
    const invalid = zones.add(.{ .suffix = ".bad", .action = .warn, .weight = 1, .reason = "bad" });
    const too_long = zones.add(.{ .suffix = "toolong.example", .action = .warn, .weight = 1, .reason = "long" });

    // Assert.
    try testing.expectError(error.InvalidSuffix, invalid);
    try testing.expectError(error.SuffixTooLong, too_long);
}
