//! IRCv3 Strict Transport Security (STS).
//!
//! The module owns only STS value formatting/parsing and the client cache
//! decision surface. Callers provide time, connection security state, and all
//! storage so protocol hot paths do not allocate.
const std = @import("std");

pub const CAP_NAME = "sts";
pub const MAX_VALUE_LEN: usize = 96;

pub const StsError = error{
    DuplicateKey,
    HostStorageFull,
    HostTooLong,
    InvalidDuration,
    InvalidHost,
    InvalidPolicy,
    InvalidPort,
    InvalidToken,
    MissingDuration,
    MissingPort,
    OutputTooSmall,
    TooManyPolicies,
};

/// Parsed or to-be-advertised STS value.
///
/// `duration_seconds == 0` is valid and disables a stored persistence policy.
pub const Value = struct {
    duration_seconds: ?u64 = null,
    port: ?u16 = null,
    preload: bool = false,
};

/// Server-side STS configuration helper.
pub const Advertisement = struct {
    duration_seconds: ?u64 = null,
    port: ?u16 = null,
    preload: bool = false,

    pub fn value(self: Advertisement) Value {
        return .{
            .duration_seconds = self.duration_seconds,
            .port = self.port,
            .preload = self.preload,
        };
    }
};

/// Client-side cached STS policy view.
pub const PolicyView = struct {
    host: []const u8,
    port: u16,
    duration_seconds: u64,
    expiry_ms: i64,
    preload: bool,

    pub fn active(self: PolicyView, now_ms: i64) bool {
        return now_ms < self.expiry_ms;
    }
};

/// Caller-provided storage for client-side policies.
pub const PolicyStore = struct {
    entries: []Entry,
    host_storage: []u8,
    count: usize = 0,
    used: usize = 0,

    pub const Entry = struct {
        host_start: usize,
        host_len: usize,
        port: u16,
        duration_seconds: u64,
        expiry_ms: i64,
        preload: bool,
    };

    pub fn init(entries: []Entry, host_storage: []u8) PolicyStore {
        return .{ .entries = entries, .host_storage = host_storage };
    }

    /// Store, update, or clear a persistence policy received on a secure link.
    pub fn applySecure(
        self: *PolicyStore,
        host: []const u8,
        value: Value,
        current_secure_port: u16,
        now_ms: i64,
    ) StsError!void {
        const duration = value.duration_seconds orelse return error.MissingDuration;
        const port = value.port orelse current_secure_port;
        try validatePort(port);

        var canonical: [MAX_HOST_LEN]u8 = undefined;
        const normalized = try normalizeHost(host, &canonical);
        if (duration == 0) {
            self.removeNormalized(normalized);
            return;
        }

        const expiry_ms = expiryMillis(now_ms, duration);
        if (self.findNormalized(normalized)) |index| {
            self.entries[index].port = port;
            self.entries[index].duration_seconds = duration;
            self.entries[index].expiry_ms = expiry_ms;
            self.entries[index].preload = value.preload;
            return;
        }

        if (self.count >= self.entries.len) return error.TooManyPolicies;
        if (self.used + normalized.len > self.host_storage.len) return error.HostStorageFull;

        const start = self.used;
        @memcpy(self.host_storage[start .. start + normalized.len], normalized);
        self.used += normalized.len;
        self.entries[self.count] = .{
            .host_start = start,
            .host_len = normalized.len,
            .port = port,
            .duration_seconds = duration,
            .expiry_ms = expiry_ms,
            .preload = value.preload,
        };
        self.count += 1;
    }

    /// Return the secure port required before making an insecure connection.
    pub fn upgradePort(self: *PolicyStore, host: []const u8, now_ms: i64) StsError!?u16 {
        var canonical: [MAX_HOST_LEN]u8 = undefined;
        const normalized = try normalizeHost(host, &canonical);
        const index = self.findNormalized(normalized) orelse return null;
        if (now_ms >= self.entries[index].expiry_ms) {
            self.removeAt(index);
            return null;
        }
        return self.entries[index].port;
    }

    /// Parse an insecure advertisement and return the immediate upgrade port.
    pub fn advertisedUpgradePort(value: Value) StsError!u16 {
        return value.port orelse error.MissingPort;
    }

    /// Reschedule a still-active policy when a connection closes.
    pub fn reschedule(self: *PolicyStore, host: []const u8, now_ms: i64) StsError!bool {
        var canonical: [MAX_HOST_LEN]u8 = undefined;
        const normalized = try normalizeHost(host, &canonical);
        const index = self.findNormalized(normalized) orelse return false;
        if (now_ms >= self.entries[index].expiry_ms) {
            self.removeAt(index);
            return false;
        }
        self.entries[index].expiry_ms = expiryMillis(now_ms, self.entries[index].duration_seconds);
        return true;
    }

    pub fn get(self: *PolicyStore, host: []const u8, now_ms: i64) StsError!?PolicyView {
        var canonical: [MAX_HOST_LEN]u8 = undefined;
        const normalized = try normalizeHost(host, &canonical);
        const index = self.findNormalized(normalized) orelse return null;
        if (now_ms >= self.entries[index].expiry_ms) {
            self.removeAt(index);
            return null;
        }
        return self.viewAt(index);
    }

    pub fn len(self: *const PolicyStore) usize {
        return self.count;
    }

    fn viewAt(self: *const PolicyStore, index: usize) PolicyView {
        const entry = self.entries[index];
        return .{
            .host = self.host_storage[entry.host_start .. entry.host_start + entry.host_len],
            .port = entry.port,
            .duration_seconds = entry.duration_seconds,
            .expiry_ms = entry.expiry_ms,
            .preload = entry.preload,
        };
    }

    fn findNormalized(self: *const PolicyStore, normalized: []const u8) ?usize {
        var index: usize = 0;
        while (index < self.count) : (index += 1) {
            const entry = self.entries[index];
            const host = self.host_storage[entry.host_start .. entry.host_start + entry.host_len];
            if (std.mem.eql(u8, host, normalized)) return index;
        }
        return null;
    }

    fn removeNormalized(self: *PolicyStore, normalized: []const u8) void {
        if (self.findNormalized(normalized)) |index| {
            self.removeAt(index);
        }
    }

    fn removeAt(self: *PolicyStore, index: usize) void {
        const entry = self.entries[index];
        const host_end = entry.host_start + entry.host_len;
        const tail_len = self.used - host_end;

        if (tail_len != 0) {
            std.mem.copyForwards(
                u8,
                self.host_storage[entry.host_start .. entry.host_start + tail_len],
                self.host_storage[host_end .. host_end + tail_len],
            );
        }
        self.used -= entry.host_len;

        var adjust: usize = 0;
        while (adjust < self.count) : (adjust += 1) {
            if (adjust == index) continue;
            if (self.entries[adjust].host_start > entry.host_start) {
                self.entries[adjust].host_start -= entry.host_len;
            }
        }

        var move = index;
        while (move + 1 < self.count) : (move += 1) {
            self.entries[move] = self.entries[move + 1];
        }
        self.count -= 1;
    }
};

pub const MAX_HOST_LEN: usize = 255;

/// Fixed-size policy store for callers that prefer comptime capacities.
pub fn FixedPolicyStore(comptime max_policies: usize, comptime host_bytes: usize) type {
    return struct {
        const Self = @This();

        entries: [max_policies]PolicyStore.Entry = undefined,
        hosts: [host_bytes]u8 = undefined,
        count: usize = 0,
        used: usize = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn applySecure(
            self: *Self,
            host: []const u8,
            value: Value,
            current_secure_port: u16,
            now_ms: i64,
        ) StsError!void {
            var store = self.storeView();
            try store.applySecure(host, value, current_secure_port, now_ms);
            self.sync(store);
        }

        pub fn upgradePort(self: *Self, host: []const u8, now_ms: i64) StsError!?u16 {
            var store = self.storeView();
            const port = try store.upgradePort(host, now_ms);
            self.sync(store);
            return port;
        }

        pub fn reschedule(self: *Self, host: []const u8, now_ms: i64) StsError!bool {
            var store = self.storeView();
            const changed = try store.reschedule(host, now_ms);
            self.sync(store);
            return changed;
        }

        pub fn get(self: *Self, host: []const u8, now_ms: i64) StsError!?PolicyView {
            var store = self.storeView();
            const policy = try store.get(host, now_ms);
            self.sync(store);
            return policy;
        }

        pub fn len(self: *const Self) usize {
            return self.count;
        }

        fn storeView(self: *Self) PolicyStore {
            return .{
                .entries = &self.entries,
                .host_storage = &self.hosts,
                .count = self.count,
                .used = self.used,
            };
        }

        fn sync(self: *Self, store: PolicyStore) void {
            self.count = store.count;
            self.used = store.used;
        }
    };
}

/// Write the comma-separated STS capability value into caller storage.
pub fn writeValue(value: Value, out: []u8) StsError![]const u8 {
    var len: usize = 0;

    if (value.duration_seconds) |duration| {
        len = try appendFieldName(out, len, "duration=");
        len = try appendInt(u64, out, len, duration);
    }
    if (value.port) |port| {
        try validatePort(port);
        len = try appendComma(out, len);
        len = try appendFieldName(out, len, "port=");
        len = try appendInt(u16, out, len, port);
    }
    if (value.preload) {
        len = try appendComma(out, len);
        len = try appendFieldName(out, len, "preload");
    }

    if (len == 0) return error.InvalidPolicy;
    return out[0..len];
}

/// Write `sts=<value>` for CAP LS/NEW advertisements.
pub fn writeAdvertisement(advertisement: Advertisement, out: []u8) StsError![]const u8 {
    if (CAP_NAME.len + 1 > out.len) return error.OutputTooSmall;
    @memcpy(out[0..CAP_NAME.len], CAP_NAME);
    out[CAP_NAME.len] = '=';
    const value = try writeValue(advertisement.value(), out[CAP_NAME.len + 1 ..]);
    return out[0 .. CAP_NAME.len + 1 + value.len];
}

/// Parse a comma-separated STS capability value.
pub fn parseValue(input: []const u8) StsError!Value {
    if (input.len == 0 or input.len > MAX_VALUE_LEN) return error.InvalidPolicy;

    var value = Value{};
    var saw_duration = false;
    var saw_port = false;
    var saw_preload = false;
    var saw_token = false;
    var cursor: usize = 0;

    while (cursor <= input.len) {
        const next = findByte(input, cursor, ',') orelse input.len;
        if (next == cursor) return error.InvalidToken;

        const token = input[cursor..next];
        try validateTokenBytes(token);
        const split = findByte(token, 0, '=');
        const key = if (split) |pos| token[0..pos] else token;
        const raw = if (split) |pos| token[pos + 1 ..] else null;
        if (!validKey(key)) return error.InvalidToken;

        if (std.mem.eql(u8, key, "duration")) {
            if (saw_duration) return error.DuplicateKey;
            const raw_duration = raw orelse return error.InvalidDuration;
            value.duration_seconds = try parseDuration(raw_duration);
            saw_duration = true;
        } else if (std.mem.eql(u8, key, "port")) {
            if (saw_port) return error.DuplicateKey;
            const raw_port = raw orelse return error.InvalidPort;
            value.port = try parsePort(raw_port);
            saw_port = true;
        } else if (std.mem.eql(u8, key, "preload")) {
            if (saw_preload) return error.DuplicateKey;
            value.preload = true;
            saw_preload = true;
        }

        saw_token = true;
        if (next == input.len) break;
        cursor = next + 1;
    }

    if (!saw_token) return error.InvalidPolicy;
    return value;
}

pub fn requireSecurePersistence(value: Value) StsError!u64 {
    return value.duration_seconds orelse error.MissingDuration;
}

pub fn requireInsecureUpgrade(value: Value) StsError!u16 {
    return value.port orelse error.MissingPort;
}

fn appendComma(out: []u8, len: usize) StsError!usize {
    if (len == 0) return len;
    if (len == out.len) return error.OutputTooSmall;
    out[len] = ',';
    return len + 1;
}

fn appendFieldName(out: []u8, len: usize, name: []const u8) StsError!usize {
    if (len + name.len > out.len) return error.OutputTooSmall;
    @memcpy(out[len .. len + name.len], name);
    return len + name.len;
}

fn appendInt(comptime T: type, out: []u8, len: usize, value: T) StsError!usize {
    const written = std.fmt.bufPrint(out[len..], "{}", .{value}) catch return error.OutputTooSmall;
    return len + written.len;
}

fn parseDuration(raw: []const u8) StsError!u64 {
    if (!allDigits(raw)) return error.InvalidDuration;
    return std.fmt.parseInt(u64, raw, 10) catch return error.InvalidDuration;
}

fn parsePort(raw: []const u8) StsError!u16 {
    if (!allDigits(raw)) return error.InvalidPort;
    const port = std.fmt.parseInt(u16, raw, 10) catch return error.InvalidPort;
    try validatePort(port);
    return port;
}

fn validatePort(port: u16) StsError!void {
    if (port == 0) return error.InvalidPort;
}

fn allDigits(raw: []const u8) bool {
    if (raw.len == 0) return false;
    for (raw) |ch| {
        if (ch < '0' or ch > '9') return false;
    }
    return true;
}

fn validateTokenBytes(token: []const u8) StsError!void {
    for (token) |ch| {
        switch (ch) {
            0...' ', 0x7f => return error.InvalidToken,
            else => {},
        }
    }
}

fn validKey(key: []const u8) bool {
    if (key.len == 0) return false;
    for (key) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '/', '.' => {},
            else => return false,
        }
    }
    return true;
}

fn normalizeHost(host: []const u8, out: []u8) StsError![]const u8 {
    if (host.len == 0) return error.InvalidHost;
    if (host.len > MAX_HOST_LEN or host.len > out.len) return error.HostTooLong;

    for (host, 0..) |ch, i| {
        switch (ch) {
            'A'...'Z' => out[i] = ch + ('a' - 'A'),
            'a'...'z', '0'...'9', '.', '-', '_', ':', '[', ']' => out[i] = ch,
            else => return error.InvalidHost,
        }
    }
    return out[0..host.len];
}

fn expiryMillis(now_ms: i64, duration_seconds: u64) i64 {
    const max = std.math.maxInt(i64);
    if (duration_seconds > @divTrunc(@as(u64, @intCast(max)), 1000)) return max;
    const delta_ms = duration_seconds * 1000;
    if (now_ms > max - @as(i64, @intCast(delta_ms))) return max;
    return now_ms + @as(i64, @intCast(delta_ms));
}

fn findByte(bytes: []const u8, start: usize, needle: u8) ?usize {
    var cursor = start;
    while (cursor < bytes.len) : (cursor += 1) {
        if (bytes[cursor] == needle) return cursor;
    }
    return null;
}

test "build and parse value round trip" {
    var buf: [MAX_VALUE_LEN]u8 = undefined;
    const written = try writeValue(.{
        .duration_seconds = 2_592_000,
        .port = 6697,
        .preload = true,
    }, &buf);
    try std.testing.expectEqualStrings("duration=2592000,port=6697,preload", written);

    const parsed = try parseValue(written);
    try std.testing.expectEqual(@as(?u64, 2_592_000), parsed.duration_seconds);
    try std.testing.expectEqual(@as(?u16, 6697), parsed.port);
    try std.testing.expect(parsed.preload);
}

test "policy expiry removes upgrade requirement" {
    const entries = try std.testing.allocator.alloc(PolicyStore.Entry, 2);
    defer std.testing.allocator.free(entries);
    const hosts = try std.testing.allocator.alloc(u8, 64);
    defer std.testing.allocator.free(hosts);
    var store = PolicyStore.init(entries, hosts);

    try store.applySecure("IRC.Example.NET", try parseValue("duration=5,port=6697"), 7000, 1000);
    try std.testing.expectEqual(@as(?u16, 6697), try store.upgradePort("irc.example.net", 5999));
    try std.testing.expectEqual(@as(?u16, null), try store.upgradePort("irc.example.net", 6000));
    try std.testing.expectEqual(@as(usize, 0), store.len());
}

test "upgrade decision when policy is present" {
    var entries: [1]PolicyStore.Entry = undefined;
    var hosts: [64]u8 = undefined;
    var store = PolicyStore.init(&entries, &hosts);

    try store.applySecure("irc.example.net", try parseValue("duration=60"), 6697, 10_000);
    try std.testing.expectEqual(@as(?u16, 6697), try store.upgradePort("IRC.EXAMPLE.NET", 11_000));
}

test "malformed value rejected" {
    try std.testing.expectError(error.InvalidPort, parseValue("duration=60,port=0"));
    try std.testing.expectError(error.DuplicateKey, parseValue("duration=60,duration=61"));
    try std.testing.expectError(error.InvalidDuration, parseValue("duration=abc"));
    try std.testing.expectError(error.InvalidToken, parseValue("duration=60,,port=6697"));
}

test "server advertisement helper writes cap token" {
    var buf: [MAX_VALUE_LEN]u8 = undefined;
    const written = try writeAdvertisement(.{
        .duration_seconds = 604800,
        .port = 6697,
    }, &buf);
    try std.testing.expectEqualStrings("sts=duration=604800,port=6697", written);
}

test "secure duration zero clears policy" {
    var entries: [1]PolicyStore.Entry = undefined;
    var hosts: [64]u8 = undefined;
    var store = PolicyStore.init(&entries, &hosts);

    try store.applySecure("irc.example.net", try parseValue("duration=60"), 6697, 0);
    try store.applySecure("irc.example.net", try parseValue("duration=0"), 6697, 1000);
    try std.testing.expectEqual(@as(?u16, null), try store.upgradePort("irc.example.net", 1001));
}

test "unknown tokens are ignored" {
    const parsed = try parseValue("unknown,duration=31536000,foo=bar,preload=yes");
    try std.testing.expectEqual(@as(?u64, 31_536_000), parsed.duration_seconds);
    try std.testing.expectEqual(@as(?u16, null), parsed.port);
    try std.testing.expect(parsed.preload);
}

test "fixed policy store supports comptime capacities" {
    var fixed = FixedPolicyStore(1, 64).init();
    try fixed.applySecure("irc.example.net", try parseValue("duration=1"), 6697, 0);
    try std.testing.expectEqual(@as(?u16, 6697), try fixed.upgradePort("irc.example.net", 999));
}
