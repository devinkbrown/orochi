// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 draft/read-marker state and MARKREAD framing.
//!
//! Read markers are local to one authenticated user/client family: callers key
//! storage by their own stable client/account id and a single channel or query
//! target. The hot paths are allocation-free: parsing borrows caller slices,
//! response writers use caller-owned buffers, and the store is a fixed-size
//! open-addressed table.
const std = @import("std");

pub const ClientId = u64;
pub const default_max_target_bytes: usize = 128;
pub const timestamp_param_prefix = "timestamp=";
pub const timestamp_wire_len: usize = 24;
pub const timestamp_param_len: usize = timestamp_param_prefix.len + timestamp_wire_len;

/// Errors returned for attacker-controlled MARKREAD input and bounded output.
pub const ReadMarkerError = error{
    MissingParameter,
    TooManyParameters,
    InvalidTarget,
    InvalidTimestamp,
    TargetLimitExceeded,
    OutputTooSmall,
};

/// Validated server-time UTC millisecond timestamp.
///
/// Stored as the fixed `YYYY-MM-DDThh:mm:ss.sssZ` wire form. Since the format
/// is fixed-width UTC, lexicographic order is chronological after validation.
pub const ReadTimestamp = struct {
    bytes: [timestamp_wire_len]u8 = [_]u8{0} ** timestamp_wire_len,

    pub fn parseParam(value: []const u8) ReadMarkerError!ReadTimestamp {
        if (!std.mem.startsWith(u8, value, timestamp_param_prefix)) return error.InvalidTimestamp;
        return parseWire(value[timestamp_param_prefix.len..]);
    }

    pub fn parseWire(value: []const u8) ReadMarkerError!ReadTimestamp {
        if (!validTimestampWire(value)) return error.InvalidTimestamp;

        var timestamp = ReadTimestamp{};
        @memcpy(&timestamp.bytes, value);
        return timestamp;
    }

    pub fn slice(self: *const ReadTimestamp) []const u8 {
        return self.bytes[0..];
    }

    pub fn compare(self: ReadTimestamp, other: ReadTimestamp) std.math.Order {
        return std.mem.order(u8, self.slice(), other.slice());
    }

    pub fn newerThan(self: ReadTimestamp, other: ReadTimestamp) bool {
        return self.compare(other) == .gt;
    }
};

/// Stored marker value. `unset` emits the draft-required literal `*`.
pub const Marker = union(enum) {
    unset,
    timestamp: ReadTimestamp,
};

/// Parsed client MARKREAD command.
pub const MarkReadCommand = union(enum) {
    get: []const u8,
    set: SetCommand,
};

pub const SetCommand = struct {
    target: []const u8,
    timestamp: ReadTimestamp,
};

/// Result of applying a client set command.
pub const SetResult = struct {
    marker: Marker,
    changed: bool,
};

/// Fixed-size store configuration.
pub const Config = struct {
    max_markers: usize = 1024,
    max_target_bytes: usize = default_max_target_bytes,
};

/// Parse a client `MARKREAD` parameter list with the default target bound.
pub fn parseClient(params: []const []const u8) ReadMarkerError!MarkReadCommand {
    return parseClientBounded(default_max_target_bytes, params);
}

/// Parse a client `MARKREAD` parameter list.
///
/// Accepted forms are `MARKREAD <target>` and
/// `MARKREAD <target> timestamp=YYYY-MM-DDThh:mm:ss.sssZ`. Client set commands
/// using `*` are rejected; only server responses may carry the unset marker.
pub fn parseClientBounded(
    comptime max_target_bytes: usize,
    params: []const []const u8,
) ReadMarkerError!MarkReadCommand {
    if (params.len == 0) return error.MissingParameter;
    if (params.len > 2) return error.TooManyParameters;
    if (!validTarget(params[0], max_target_bytes)) return error.InvalidTarget;

    if (params.len == 1) return .{ .get = params[0] };
    if (std.mem.eql(u8, params[1], "*")) return error.InvalidTimestamp;

    return .{ .set = .{
        .target = params[0],
        .timestamp = try ReadTimestamp.parseParam(params[1]),
    } };
}

/// Build `MARKREAD <target> <timestamp|*>` into `out`.
pub fn writeResponse(target: []const u8, marker: Marker, out: []u8) ReadMarkerError![]const u8 {
    return writeResponseBounded(default_max_target_bytes, target, marker, out);
}

/// Build `MARKREAD <target> <timestamp|*>` with a caller-selected target bound.
pub fn writeResponseBounded(
    comptime max_target_bytes: usize,
    target: []const u8,
    marker: Marker,
    out: []u8,
) ReadMarkerError![]const u8 {
    if (!validTarget(target, max_target_bytes)) return error.InvalidTarget;

    var cursor: usize = 0;
    try appendSlice(out, &cursor, "MARKREAD ");
    try appendSlice(out, &cursor, target);
    try appendByte(out, &cursor, ' ');
    try appendMarkerParam(out, &cursor, marker);
    try appendSlice(out, &cursor, "\r\n");
    return out[0..cursor];
}

/// Build `:<server> MARKREAD <target> <timestamp|*>` into `out`.
pub fn writeServerResponse(
    server_name: []const u8,
    target: []const u8,
    marker: Marker,
    out: []u8,
) ReadMarkerError![]const u8 {
    return writeServerResponseBounded(default_max_target_bytes, server_name, target, marker, out);
}

/// Build a prefixed server MARKREAD response with a caller-selected target bound.
pub fn writeServerResponseBounded(
    comptime max_target_bytes: usize,
    server_name: []const u8,
    target: []const u8,
    marker: Marker,
    out: []u8,
) ReadMarkerError![]const u8 {
    if (!validServerName(server_name)) return error.InvalidTarget;
    if (!validTarget(target, max_target_bytes)) return error.InvalidTarget;

    var cursor: usize = 0;
    try appendByte(out, &cursor, ':');
    try appendSlice(out, &cursor, server_name);
    try appendSlice(out, &cursor, " MARKREAD ");
    try appendSlice(out, &cursor, target);
    try appendByte(out, &cursor, ' ');
    try appendMarkerParam(out, &cursor, marker);
    try appendSlice(out, &cursor, "\r\n");
    return out[0..cursor];
}

/// Fixed-size per-client/per-target read marker table.
pub fn ReadMarkerStore(comptime config: Config) type {
    comptime {
        if (config.max_markers == 0) @compileError("ReadMarkerStore needs at least one marker slot");
        if (config.max_target_bytes == 0) @compileError("target names need storage");
        if (config.max_target_bytes > std.math.maxInt(u8)) @compileError("target length is stored in u8");
    }

    const TargetKey = struct {
        const Key = @This();

        client: ClientId = 0,
        target: [config.max_target_bytes]u8 = [_]u8{0} ** config.max_target_bytes,
        target_len: u8 = 0,

        fn init(client: ClientId, target: []const u8) ReadMarkerError!Key {
            if (!validTarget(target, config.max_target_bytes)) return error.InvalidTarget;

            var key = Key{ .client = client, .target_len = @intCast(target.len) };
            for (target, 0..) |ch, index| {
                key.target[index] = normalizeTargetByte(ch);
            }
            return key;
        }

        fn slice(self: *const Key) []const u8 {
            return self.target[0..self.target_len];
        }

        fn eql(self: *const Key, other: *const Key) bool {
            return self.client == other.client and
                self.target_len == other.target_len and
                std.mem.eql(u8, self.slice(), other.slice());
        }

        fn hash(self: *const Key) u64 {
            var hasher = std.hash.Wyhash.init(0x6d_7a_72_65_61_64_6d_72);
            var client_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &client_bytes, self.client, .little);
            hasher.update(&client_bytes);
            hasher.update(self.slice());
            return hasher.final();
        }
    };

    const Entry = struct {
        occupied: bool = false,
        key: TargetKey = .{},
        timestamp: ReadTimestamp = .{},
    };

    return struct {
        const Self = @This();

        entries: [config.max_markers]Entry = [_]Entry{.{}} ** config.max_markers,
        len: usize = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// Get the stored marker for `client` and `target`, or `unset`.
        pub fn get(self: *const Self, client: ClientId, target: []const u8) ReadMarkerError!Marker {
            const key = try TargetKey.init(client, target);
            const slot = self.findExisting(key) orelse return .unset;
            return .{ .timestamp = self.entries[slot].timestamp };
        }

        /// Apply a monotonic read-marker update.
        ///
        /// Older or equal timestamps are ignored and the stored newer marker is
        /// returned so the caller can echo the authoritative value to the
        /// submitting client.
        pub fn set(
            self: *Self,
            client: ClientId,
            target: []const u8,
            timestamp: ReadTimestamp,
        ) ReadMarkerError!SetResult {
            const key = try TargetKey.init(client, target);
            const lookup = try self.findForPut(key);

            if (self.entries[lookup.index].occupied) {
                const stored = self.entries[lookup.index].timestamp;
                if (!timestamp.newerThan(stored)) {
                    return .{ .marker = .{ .timestamp = stored }, .changed = false };
                }
                self.entries[lookup.index].timestamp = timestamp;
                return .{ .marker = .{ .timestamp = timestamp }, .changed = true };
            }

            self.entries[lookup.index] = .{
                .occupied = true,
                .key = key,
                .timestamp = timestamp,
            };
            self.len += 1;
            return .{ .marker = .{ .timestamp = timestamp }, .changed = true };
        }

        fn findExisting(self: *const Self, key: TargetKey) ?usize {
            var index = @as(usize, @intCast(key.hash() % config.max_markers));
            var probes: usize = 0;

            while (probes < config.max_markers) : (probes += 1) {
                const entry = &self.entries[index];
                if (!entry.occupied) return null;
                if (entry.key.eql(&key)) return index;
                index = (index + 1) % config.max_markers;
            }
            return null;
        }

        fn findForPut(self: *const Self, key: TargetKey) ReadMarkerError!struct { index: usize } {
            var index = @as(usize, @intCast(key.hash() % config.max_markers));
            var probes: usize = 0;

            while (probes < config.max_markers) : (probes += 1) {
                const entry = &self.entries[index];
                if (!entry.occupied or entry.key.eql(&key)) return .{ .index = index };
                index = (index + 1) % config.max_markers;
            }

            return error.TargetLimitExceeded;
        }
    };
}

pub const DefaultStore = ReadMarkerStore(.{});

pub fn validTarget(target: []const u8, comptime max_target_bytes: usize) bool {
    if (target.len == 0 or target.len > max_target_bytes) return false;

    for (target) |ch| {
        if (ch <= ' ' or ch == 0x7f) return false;
        if (ch == ',' or ch == ':') return false;
    }

    return true;
}

fn validServerName(name: []const u8) bool {
    if (name.len == 0 or name.len > 255) return false;

    for (name) |ch| {
        if (ch <= ' ' or ch == 0x7f) return false;
        if (ch == ':') return false;
    }

    return true;
}

fn appendMarkerParam(out: []u8, cursor: *usize, marker: Marker) ReadMarkerError!void {
    switch (marker) {
        .unset => try appendByte(out, cursor, '*'),
        .timestamp => |timestamp| {
            try appendSlice(out, cursor, timestamp_param_prefix);
            try appendSlice(out, cursor, timestamp.slice());
        },
    }
}

fn appendSlice(out: []u8, cursor: *usize, bytes: []const u8) ReadMarkerError!void {
    if (cursor.* + bytes.len > out.len) return error.OutputTooSmall;
    @memcpy(out[cursor.* .. cursor.* + bytes.len], bytes);
    cursor.* += bytes.len;
}

fn appendByte(out: []u8, cursor: *usize, byte: u8) ReadMarkerError!void {
    if (cursor.* >= out.len) return error.OutputTooSmall;
    out[cursor.*] = byte;
    cursor.* += 1;
}

fn normalizeTargetByte(ch: u8) u8 {
    return switch (ch) {
        'A'...'Z' => ch + ('a' - 'A'),
        else => ch,
    };
}

fn validTimestampWire(value: []const u8) bool {
    if (value.len != timestamp_wire_len) return false;

    if (value[4] != '-' or value[7] != '-' or value[10] != 'T' or
        value[13] != ':' or value[16] != ':' or value[19] != '.' or value[23] != 'Z')
    {
        return false;
    }

    if (!allDigits(value[0..4]) or !allDigits(value[5..7]) or
        !allDigits(value[8..10]) or !allDigits(value[11..13]) or
        !allDigits(value[14..16]) or !allDigits(value[17..19]) or
        !allDigits(value[20..23]))
    {
        return false;
    }

    const year = parseUnsigned(value[0..4]);
    const month = parseUnsigned(value[5..7]);
    const day = parseUnsigned(value[8..10]);
    const hour = parseUnsigned(value[11..13]);
    const minute = parseUnsigned(value[14..16]);
    const second = parseUnsigned(value[17..19]);
    const millisecond = parseUnsigned(value[20..23]);

    if (year == 0) return false;
    if (month < 1 or month > 12) return false;
    if (day < 1 or day > daysInMonth(@intCast(year), @intCast(month))) return false;
    if (hour > 23 or minute > 59 or second > 59 or millisecond > 999) return false;

    return true;
}

fn allDigits(value: []const u8) bool {
    for (value) |ch| {
        if (ch < '0' or ch > '9') return false;
    }
    return true;
}

fn parseUnsigned(value: []const u8) u32 {
    var result: u32 = 0;
    for (value) |ch| {
        result = result * 10 + @as(u32, ch - '0');
    }
    return result;
}

fn daysInMonth(year: u16, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => 0,
    };
}

fn isLeapYear(year: u16) bool {
    return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
}

test "set and get round-trip with response emission" {
    var store = DefaultStore.init();
    const params = [_][]const u8{ "#Suzu", "timestamp=2026-06-02T08:09:10.123Z" };

    const parsed = try parseClient(&params);
    const set = switch (parsed) {
        .set => |value| value,
        .get => return error.InvalidTimestamp,
    };

    const result = try store.set(7, set.target, set.timestamp);
    try std.testing.expect(result.changed);

    const got = try store.get(7, "#suzu");
    const timestamp = switch (got) {
        .timestamp => |value| value,
        .unset => return error.InvalidTimestamp,
    };
    try std.testing.expectEqualStrings("2026-06-02T08:09:10.123Z", timestamp.slice());

    var line_buf: [96]u8 = undefined;
    const line = try writeResponse("#Suzu", result.marker, &line_buf);
    try std.testing.expectEqualStrings(
        "MARKREAD #Suzu timestamp=2026-06-02T08:09:10.123Z\r\n",
        line,
    );
}

test "backward update is ignored" {
    var store = DefaultStore.init();
    const newer = try ReadTimestamp.parseParam("timestamp=2026-06-02T08:09:10.123Z");
    const older = try ReadTimestamp.parseParam("timestamp=2026-06-02T08:09:09.999Z");

    try std.testing.expect((try store.set(9, "#chan", newer)).changed);
    const result = try store.set(9, "#chan", older);
    try std.testing.expect(!result.changed);

    const marker = try store.get(9, "#CHAN");
    const stored = switch (marker) {
        .timestamp => |value| value,
        .unset => return error.InvalidTimestamp,
    };
    try std.testing.expectEqualStrings("2026-06-02T08:09:10.123Z", stored.slice());
}

test "unset marker returns star" {
    var store = DefaultStore.init();
    const marker = try store.get(1, "queryNick");

    var line_buf: [64]u8 = undefined;
    const line = try writeServerResponse("irc.example", "queryNick", marker, &line_buf);
    try std.testing.expectEqualStrings(":irc.example MARKREAD queryNick *\r\n", line);
}

test "malformed commands are rejected" {
    const empty = [_][]const u8{};
    try std.testing.expectError(error.MissingParameter, parseClient(&empty));

    const too_many = [_][]const u8{ "#chan", "timestamp=2026-06-02T08:09:10.123Z", "extra" };
    try std.testing.expectError(error.TooManyParameters, parseClient(&too_many));

    const unset_set = [_][]const u8{ "#chan", "*" };
    try std.testing.expectError(error.InvalidTimestamp, parseClient(&unset_set));

    const invalid_date = [_][]const u8{ "#chan", "timestamp=2026-02-29T08:09:10.123Z" };
    try std.testing.expectError(error.InvalidTimestamp, parseClient(&invalid_date));

    const bad_target = [_][]const u8{"#bad,target"};
    try std.testing.expectError(error.InvalidTarget, parseClient(&bad_target));
}

test "bounded targets and fixed marker capacity" {
    const SmallStore = ReadMarkerStore(.{ .max_markers = 2, .max_target_bytes = 5 });
    var store = SmallStore.init();

    const ts = try ReadTimestamp.parseParam("timestamp=2026-06-02T08:09:10.123Z");
    try std.testing.expectError(error.InvalidTarget, store.set(1, "#toolong", ts));

    try std.testing.expect((try store.set(1, "#one", ts)).changed);
    try std.testing.expect((try store.set(1, "#two", ts)).changed);
    try std.testing.expectError(error.TargetLimitExceeded, store.set(1, "#tre", ts));
}
