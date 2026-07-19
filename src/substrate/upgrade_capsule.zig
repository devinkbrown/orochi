// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed Helix /UPGRADE migration capsule.
//!
//! The capsule is a pure byte format for handing minimal live-session state to a
//! replacement image during an in-place restart. It records only fd numbers and
//! IRC session identity/capability/channel membership state; it never forks,
//! execs, duplicates fds, or inspects process state.
const std = @import("std");

const Allocator = std.mem.Allocator;

pub const item_id: u8 = 99;
pub const version: u16 = 1;
pub const magic: [4]u8 = .{ 'M', 'Z', 'U', 'C' };

pub const RegisteredFlags = packed struct(u8) {
    nick: bool = false,
    user: bool = false,
    complete: bool = false,
    _reserved: u5 = 0,

    pub fn bits(self: RegisteredFlags) u8 {
        return @bitCast(self);
    }

    pub fn fromBits(raw: u8) Error!RegisteredFlags {
        const flags: RegisteredFlags = @bitCast(raw);
        if (flags._reserved != 0) return error.InvalidFlags;
        return flags;
    }
};

pub const Bounds = struct {
    max_listeners: usize = 64,
    max_connections: usize = 16_384,
    max_channels_per_connection: usize = 512,
    max_nick_len: usize = 64,
    max_channel_len: usize = 128,
    max_buffer_bytes: usize = 16 * 1024 * 1024,

    pub fn validate(self: Bounds) Error!void {
        if (self.max_listeners == 0) return error.InvalidBounds;
        if (self.max_connections == 0) return error.InvalidBounds;
        if (self.max_nick_len == 0) return error.InvalidBounds;
        if (self.max_channel_len == 0) return error.InvalidBounds;
        if (self.max_buffer_bytes < header_len) return error.InvalidBounds;
    }
};

pub const ConnectionInput = struct {
    fd: i32,
    nick: []const u8 = "",
    registered: RegisteredFlags = .{},
    caps: u64 = 0,
    channels: []const []const u8 = &.{},
};

pub const SessionInput = struct {
    listener_fds: []const i32 = &.{},
    connections: []const ConnectionInput = &.{},
};

pub const Connection = struct {
    fd: i32,
    nick: []u8,
    registered: RegisteredFlags,
    caps: u64,
    channels: [][]u8,

    pub fn deinit(self: *Connection, allocator: Allocator) void {
        allocator.free(self.nick);
        // channels may contain empty placeholders (alloc'd but not yet read);
        // only free real (non-empty) entries to stay safe on partial-read cleanup.
        for (self.channels) |channel| if (channel.len != 0) allocator.free(channel);
        allocator.free(self.channels);
        self.* = .{
            .fd = -1,
            .nick = &.{},
            .registered = .{},
            .caps = 0,
            .channels = &.{},
        };
    }
};

pub const Session = struct {
    listener_fds: []i32,
    connections: []Connection,

    pub fn deinit(self: *Session, allocator: Allocator) void {
        allocator.free(self.listener_fds);
        for (self.connections) |*connection| connection.deinit(allocator);
        allocator.free(self.connections);
        self.* = .{ .listener_fds = &.{}, .connections = &.{} };
    }
};

pub const Error = Allocator.Error || error{
    InvalidBounds,
    BufferTooLarge,
    InvalidMagic,
    UnsupportedVersion,
    InvalidItem,
    InvalidFlags,
    InvalidFd,
    TooManyListeners,
    TooManyConnections,
    TooManyChannels,
    StringTooLong,
    EmptyChannel,
    Truncated,
    TrailingBytes,
    VarintOverflow,
};

const header_len = magic.len + 2 + 1;

pub fn serialize(allocator: Allocator, bounds: Bounds, session: SessionInput) Error![]u8 {
    try bounds.validate();
    try validateSession(bounds, session);

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    try out.ensureTotalCapacity(allocator, estimateSize(session));
    try out.appendSlice(allocator, &magic);
    try writeU16(&out, allocator, version);
    try out.append(allocator, item_id);

    try writeVarint(&out, allocator, session.listener_fds.len);
    for (session.listener_fds) |fd| try writeFd(&out, allocator, fd);

    try writeVarint(&out, allocator, session.connections.len);
    for (session.connections) |connection| {
        try writeFd(&out, allocator, connection.fd);
        try out.append(allocator, connection.registered.bits());
        try writeU64(&out, allocator, connection.caps);
        try writeBytes(&out, allocator, connection.nick);
        try writeVarint(&out, allocator, connection.channels.len);
        for (connection.channels) |channel| try writeBytes(&out, allocator, channel);
    }

    if (out.items.len > bounds.max_buffer_bytes) return error.BufferTooLarge;
    return out.toOwnedSlice(allocator);
}

pub fn deserialize(allocator: Allocator, bounds: Bounds, bytes: []const u8) Error!Session {
    try bounds.validate();
    if (bytes.len > bounds.max_buffer_bytes) return error.BufferTooLarge;

    var reader = Reader{ .buf = bytes };
    const got_magic = try reader.readFixed(magic.len);
    if (!std.mem.eql(u8, got_magic, &magic)) return error.InvalidMagic;
    if (try reader.readU16() != version) return error.UnsupportedVersion;
    if (try reader.readByte() != item_id) return error.InvalidItem;

    var out = Session{
        .listener_fds = &.{},
        .connections = &.{},
    };
    errdefer out.deinit(allocator);

    const listener_count = try reader.readBoundedCount(bounds.max_listeners, error.TooManyListeners);
    out.listener_fds = try allocator.alloc(i32, listener_count);
    for (out.listener_fds) |*fd| fd.* = try reader.readFd();

    const connection_count = try reader.readBoundedCount(bounds.max_connections, error.TooManyConnections);
    out.connections = try allocator.alloc(Connection, connection_count);
    for (out.connections) |*connection| connection.* = emptyConnection();

    for (out.connections) |*connection| {
        connection.* = try readConnection(allocator, bounds, &reader);
    }

    if (!reader.done()) return error.TrailingBytes;
    return out;
}

fn emptyConnection() Connection {
    return .{
        .fd = -1,
        .nick = &.{},
        .registered = .{},
        .caps = 0,
        .channels = &.{},
    };
}

fn validateSession(bounds: Bounds, session: SessionInput) Error!void {
    if (session.listener_fds.len > bounds.max_listeners) return error.TooManyListeners;
    if (session.connections.len > bounds.max_connections) return error.TooManyConnections;

    for (session.listener_fds) |fd| try validateFd(fd);
    for (session.connections) |connection| {
        try validateFd(connection.fd);
        _ = try RegisteredFlags.fromBits(connection.registered.bits());
        try validateNick(bounds, connection.nick);
        if (connection.channels.len > bounds.max_channels_per_connection) return error.TooManyChannels;
        for (connection.channels) |channel| try validateChannel(bounds, channel);
    }
}

fn validateFd(fd: i32) Error!void {
    if (fd < 0) return error.InvalidFd;
}

fn validateNick(bounds: Bounds, nick: []const u8) Error!void {
    if (nick.len > bounds.max_nick_len) return error.StringTooLong;
}

fn validateChannel(bounds: Bounds, channel: []const u8) Error!void {
    if (channel.len == 0) return error.EmptyChannel;
    if (channel.len > bounds.max_channel_len) return error.StringTooLong;
}

fn readConnection(allocator: Allocator, bounds: Bounds, reader: *Reader) Error!Connection {
    var connection = Connection{
        .fd = try reader.readFd(),
        .nick = &.{},
        .registered = try RegisteredFlags.fromBits(try reader.readByte()),
        .caps = try reader.readU64(),
        .channels = &.{},
    };
    errdefer connection.deinit(allocator);

    const nick_view = try reader.readBoundedBytes(bounds.max_nick_len);
    connection.nick = try allocator.dupe(u8, nick_view);

    const channel_count = try reader.readBoundedCount(
        bounds.max_channels_per_connection,
        error.TooManyChannels,
    );
    connection.channels = try allocator.alloc([]u8, channel_count);
    // Initialize to empty so a mid-loop read error leaves no garbage pointers;
    // cleanup is the outer connection.deinit errdefer alone (it skips empties),
    // avoiding a double-free of the channel array.
    for (connection.channels) |*channel| channel.* = &.{};

    for (connection.channels) |*channel| {
        const view = try reader.readBoundedBytes(bounds.max_channel_len);
        if (view.len == 0) return error.EmptyChannel;
        channel.* = try allocator.dupe(u8, view);
    }

    return connection;
}

fn estimateSize(session: SessionInput) usize {
    var total: usize = header_len + 10 + session.listener_fds.len * 5 + 10;
    for (session.connections) |connection| {
        total += 5 + 1 + 8 + 10 + connection.nick.len + 10;
        for (connection.channels) |channel| total += 10 + channel.len;
    }
    return total;
}

fn writeFd(out: *std.ArrayList(u8), allocator: Allocator, fd: i32) Error!void {
    try validateFd(fd);
    try writeVarint(out, allocator, @intCast(fd));
}

fn writeBytes(out: *std.ArrayList(u8), allocator: Allocator, bytes: []const u8) Error!void {
    try writeVarint(out, allocator, bytes.len);
    try out.appendSlice(allocator, bytes);
}

fn writeU16(out: *std.ArrayList(u8), allocator: Allocator, value: u16) Error!void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .little);
    try out.appendSlice(allocator, &buf);
}

fn writeU64(out: *std.ArrayList(u8), allocator: Allocator, value: u64) Error!void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    try out.appendSlice(allocator, &buf);
}

fn writeVarint(out: *std.ArrayList(u8), allocator: Allocator, value: usize) Error!void {
    var n: u64 = @intCast(value);
    while (n >= 0x80) {
        try out.append(allocator, @as(u8, @intCast(n & 0x7f)) | 0x80);
        n >>= 7;
    }
    try out.append(allocator, @intCast(n));
}

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn done(self: *const Reader) bool {
        return self.pos == self.buf.len;
    }

    fn readByte(self: *Reader) Error!u8 {
        if (self.pos >= self.buf.len) return error.Truncated;
        const byte = self.buf[self.pos];
        self.pos += 1;
        return byte;
    }

    fn readFixed(self: *Reader, len: usize) Error![]const u8 {
        if (self.buf.len - self.pos < len) return error.Truncated;
        const out = self.buf[self.pos..][0..len];
        self.pos += len;
        return out;
    }

    fn readU16(self: *Reader) Error!u16 {
        const bytes = try self.readFixed(2);
        return std.mem.readInt(u16, bytes[0..2], .little);
    }

    fn readU64(self: *Reader) Error!u64 {
        const bytes = try self.readFixed(8);
        return std.mem.readInt(u64, bytes[0..8], .little);
    }

    fn readFd(self: *Reader) Error!i32 {
        const raw = try self.readVarint();
        if (raw > @as(u64, @intCast(std.math.maxInt(i32)))) return error.InvalidFd;
        return @intCast(raw);
    }

    fn readBoundedCount(self: *Reader, max: usize, too_many: Error) Error!usize {
        const count = try self.readVarint();
        if (count > max) return too_many;
        return @intCast(count);
    }

    fn readBoundedBytes(self: *Reader, max_len: usize) Error![]const u8 {
        const len = try self.readBoundedCount(max_len, error.StringTooLong);
        return try self.readFixed(len);
    }

    fn readVarint(self: *Reader) Error!u64 {
        var shift: u6 = 0;
        var value: u64 = 0;

        while (true) {
            const byte = try self.readByte();
            value |= (@as(u64, byte & 0x7f) << shift);
            if ((byte & 0x80) == 0) return value;
            if (shift == 63) return error.VarintOverflow;
            shift += 7;
        }
    }
};

fn expectSessionEqual(expected: SessionInput, actual: *const Session) !void {
    try std.testing.expectEqual(expected.listener_fds.len, actual.listener_fds.len);
    for (expected.listener_fds, actual.listener_fds) |expected_fd, actual_fd| {
        try std.testing.expectEqual(expected_fd, actual_fd);
    }

    try std.testing.expectEqual(expected.connections.len, actual.connections.len);
    for (expected.connections, actual.connections) |expected_connection, actual_connection| {
        try std.testing.expectEqual(expected_connection.fd, actual_connection.fd);
        try std.testing.expectEqual(expected_connection.registered.bits(), actual_connection.registered.bits());
        try std.testing.expectEqual(expected_connection.caps, actual_connection.caps);
        try std.testing.expectEqualStrings(expected_connection.nick, actual_connection.nick);
        try std.testing.expectEqual(expected_connection.channels.len, actual_connection.channels.len);
        for (expected_connection.channels, actual_connection.channels) |expected_channel, actual_channel| {
            try std.testing.expectEqualStrings(expected_channel, actual_channel);
        }
    }
}

test "round-trip several sessions" {
    const allocator = std.testing.allocator;
    const bounds = Bounds{};
    const alice_channels = [_][]const u8{ "#onyx", "#ops" };
    const bob_channels = [_][]const u8{"#onyx"};
    const sessions = [_]SessionInput{
        .{},
        .{ .listener_fds = &.{ 3, 4, 9 } },
        .{
            .listener_fds = &.{ 7, 8 },
            .connections = &.{
                .{
                    .fd = 11,
                    .nick = "alice",
                    .registered = .{ .nick = true, .user = true, .complete = true },
                    .caps = 0x0000_0000_0000_1021,
                    .channels = &alice_channels,
                },
                .{
                    .fd = 12,
                    .nick = "bob",
                    .registered = .{ .nick = true },
                    .caps = 0x8000_0000_0000_0001,
                    .channels = &bob_channels,
                },
                .{
                    .fd = 13,
                    .registered = .{},
                    .caps = 0,
                    .channels = &.{},
                },
            },
        },
    };

    for (sessions) |session| {
        const encoded = try serialize(allocator, bounds, session);
        defer allocator.free(encoded);

        var decoded = try deserialize(allocator, bounds, encoded);
        defer decoded.deinit(allocator);

        try expectSessionEqual(session, &decoded);
    }
}

test "version mismatch rejected" {
    const allocator = std.testing.allocator;
    const encoded = try serialize(allocator, .{}, .{});
    defer allocator.free(encoded);

    var wrong_version = try allocator.dupe(u8, encoded);
    defer allocator.free(wrong_version);
    wrong_version[4] +%= 1;

    try std.testing.expectError(error.UnsupportedVersion, deserialize(allocator, .{}, wrong_version));
}

test "truncated buffer rejected" {
    const allocator = std.testing.allocator;
    const channels = [_][]const u8{ "#one", "#two" };
    const encoded = try serialize(allocator, .{}, .{
        .listener_fds = &.{5},
        .connections = &.{.{
            .fd = 6,
            .nick = "trudy",
            .registered = .{ .nick = true, .user = true },
            .caps = 3,
            .channels = &channels,
        }},
    });
    defer allocator.free(encoded);

    try std.testing.expect(encoded.len > header_len);
    var n: usize = 0;
    while (n < encoded.len) : (n += 1) {
        try std.testing.expectError(error.Truncated, deserialize(allocator, .{}, encoded[0..n]));
    }
}

test "invalid reserved registered flag bits rejected without leak" {
    const allocator = std.testing.allocator;
    const encoded = try serialize(allocator, .{}, .{
        .connections = &.{.{
            .fd = 10,
            .nick = "caps",
            .registered = .{ .nick = true },
            .caps = 0xff,
        }},
    });
    defer allocator.free(encoded);

    var bad = try allocator.dupe(u8, encoded);
    defer allocator.free(bad);

    var reader = Reader{ .buf = bad };
    _ = try reader.readFixed(header_len);
    _ = try reader.readVarint(); // listeners
    _ = try reader.readVarint(); // connections
    _ = try reader.readVarint(); // fd
    bad[reader.pos] = 0b1000_0000;

    try std.testing.expectError(error.InvalidFlags, deserialize(allocator, .{}, bad));
}
