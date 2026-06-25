// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 CAP LS 302 value advertisement and value-aware CAP REQ parsing.
//!
//! This module deliberately builds complete wire lines into a caller-owned sink.
//! It does not own client state or mutate negotiated capability sets.
const std = @import("std");
const cap = @import("cap.zig");

pub const MAX_LS_BODY: usize = cap.MAX_CAP_REPLY_BODY;

pub const CapValuesError = std.mem.Allocator.Error || error{
    InvalidRequest,
    OutputTooSmall,
    UnsupportedValue,
};

pub const ValueSpec = struct {
    id: cap.CapId,
    value: []const u8,
};

pub const LsOptions = struct {
    cap_302: bool = true,
    max_body: usize = MAX_LS_BODY,
    values: []const ValueSpec = &.{},
};

pub const ReqOptions = struct {
    values: []const ValueSpec = &.{},
};

pub const RequestedToken = struct {
    id: cap.CapId,
    name: []const u8,
    remove: bool = false,
    value: ?[]const u8 = null,
};

pub const Requested = struct {
    add: cap.CapSet = .{},
    remove: cap.CapSet = .{},
    token_count: usize = 0,
};

/// Convenience sink for `std.ArrayList(u8)` in Zig 0.16's allocator-explicit API.
pub const ArrayListSink = struct {
    allocator: std.mem.Allocator,
    list: *std.ArrayList(u8),

    pub fn writeAll(self: *ArrayListSink, bytes: []const u8) CapValuesError!void {
        try self.list.appendSlice(self.allocator, bytes);
    }
};

/// Emit `CAP * LS ...` wire lines, including `*` continuations when `max_body`
/// cannot hold the next capability token.
pub fn emitLs(
    registry: cap.CapRegistry,
    options: LsOptions,
    sink: anytype,
) CapValuesError!void {
    if (options.max_body == 0 or options.max_body > MAX_LS_BODY) {
        return error.OutputTooSmall;
    }

    var body: [MAX_LS_BODY]u8 = undefined;
    var body_len: usize = 0;
    var emitted_any = false;

    for (registry.specs) |spec| {
        if (spec.kind != .client or !spec.advertised) continue;

        const value = advertisedValue(spec, options);
        const token_len = spec.name.len + if (value) |v| 1 + v.len else 0;
        if (token_len > options.max_body) return error.OutputTooSmall;

        const extra_space: usize = if (body_len == 0) 0 else 1;
        if (body_len != 0 and body_len + extra_space + token_len > options.max_body) {
            try writeLsLine(sink, true, body[0..body_len]);
            emitted_any = true;
            body_len = 0;
        }

        if (body_len != 0) {
            body[body_len] = ' ';
            body_len += 1;
        }
        @memcpy(body[body_len .. body_len + spec.name.len], spec.name);
        body_len += spec.name.len;
        if (value) |v| {
            body[body_len] = '=';
            body_len += 1;
            @memcpy(body[body_len .. body_len + v.len], v);
            body_len += v.len;
        }
    }

    if (body_len != 0 or !emitted_any) {
        try writeLsLine(sink, false, body[0..body_len]);
    }
}

/// Parse a client CAP REQ list. Values are accepted only for capabilities with
/// an advertised 302 value, and requested values must match either the whole
/// advertised value or one comma-separated advertised item.
pub fn parseReq(
    registry: cap.CapRegistry,
    options: ReqOptions,
    raw_list: []const u8,
    tokens_out: ?[]RequestedToken,
) CapValuesError!Requested {
    var requested = Requested{};
    var cursor: usize = 0;
    var raw = std.mem.trim(u8, raw_list, " ");
    if (raw.len != 0 and raw[0] == ':') raw = raw[1..];

    while (cursor < raw.len) {
        while (cursor < raw.len and raw[cursor] == ' ') cursor += 1;
        if (cursor >= raw.len) break;

        const token_start = cursor;
        while (cursor < raw.len and raw[cursor] != ' ') cursor += 1;

        var token = raw[token_start..cursor];
        const remove = token.len != 0 and token[0] == '-';
        if (remove) token = token[1..];
        if (token.len == 0) return error.InvalidRequest;

        const eq_index = std.mem.indexOfScalar(u8, token, '=');
        const name = if (eq_index) |index| token[0..index] else token;
        const requested_value = if (eq_index) |index| token[index + 1 ..] else null;
        if (name.len == 0) return error.InvalidRequest;
        if (requested_value) |value| {
            if (value.len == 0) return error.UnsupportedValue;
        }

        const spec = registry.find(name) orelse return error.InvalidRequest;
        if (spec.kind != .client or !spec.advertised) return error.InvalidRequest;

        if (requested_value) |value| {
            const offered = requestValue(spec, options) orelse return error.UnsupportedValue;
            if (!valueAllowed(offered, value)) return error.UnsupportedValue;
        }

        if (tokens_out) |out| {
            if (requested.token_count >= out.len) return error.OutputTooSmall;
            out[requested.token_count] = .{
                .id = spec.id,
                .name = name,
                .remove = remove,
                .value = requested_value,
            };
        }
        requested.token_count += 1;

        if (remove) {
            requested.remove.add(spec.id);
            requested.add.remove(spec.id);
        } else {
            requested.add.add(spec.id);
            requested.remove.remove(spec.id);
        }
    }

    if (requested.token_count == 0) return error.InvalidRequest;
    return requested;
}

fn writeLsLine(sink: anytype, continuation: bool, body: []const u8) CapValuesError!void {
    try sink.writeAll("CAP * LS ");
    if (continuation) try sink.writeAll("* ");
    try sink.writeAll(":");
    try sink.writeAll(body);
    try sink.writeAll("\r\n");
}

fn advertisedValue(spec: cap.CapSpec, options: LsOptions) ?[]const u8 {
    if (!options.cap_302) return null;
    return overrideValue(spec.id, options.values) orelse spec.value_302;
}

fn requestValue(spec: cap.CapSpec, options: ReqOptions) ?[]const u8 {
    return overrideValue(spec.id, options.values) orelse spec.value_302;
}

fn overrideValue(id: cap.CapId, values: []const ValueSpec) ?[]const u8 {
    for (values) |entry| {
        if (entry.id == id) return entry.value;
    }
    return null;
}

fn valueAllowed(offered: []const u8, requested: []const u8) bool {
    if (std.mem.eql(u8, offered, requested)) return true;

    var parts = std.mem.splitScalar(u8, offered, ',');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, requested)) return true;
    }
    return false;
}

const test_values = [_]ValueSpec{
    .{ .id = .sasl, .value = "PLAIN,EXTERNAL,SCRAM-SHA-256" },
    .{ .id = .multiline, .value = "max-bytes=4096,max-lines=64" },
};

const test_specs = [_]cap.CapSpec{
    .{ .id = .server_time, .name = "server-time" },
    .{ .id = .sasl, .name = "sasl", .value_302 = "PLAIN,EXTERNAL" },
    .{ .id = .sts, .name = "sts", .value_302 = "duration=604800" },
    .{ .id = .multiline, .name = "multiline" },
};

fn testRegistry() cap.CapRegistry {
    return .{ .specs = &test_specs };
}

fn buildLs(registry: cap.CapRegistry, options: LsOptions) !std.ArrayList(u8) {
    const allocator = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    var sink = ArrayListSink{ .allocator = allocator, .list = &out };
    try emitLs(registry, options, &sink);
    return out;
}

test "LS with values emits exact CAP 302 wire bytes" {
    var out = try buildLs(testRegistry(), .{ .values = &test_values });
    defer out.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(
        "CAP * LS :server-time sasl=PLAIN,EXTERNAL,SCRAM-SHA-256 sts=duration=604800 multiline=max-bytes=4096,max-lines=64\r\n",
        out.items,
    );
}

test "LS without CAP 302 omits values exactly" {
    var out = try buildLs(testRegistry(), .{ .cap_302 = false, .values = &test_values });
    defer out.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(
        "CAP * LS :server-time sasl sts multiline\r\n",
        out.items,
    );
}

test "multi-line split emits CAP LS continuations exactly" {
    var out = try buildLs(testRegistry(), .{ .max_body = 19 });
    defer out.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(
        "CAP * LS * :server-time\r\n" ++
            "CAP * LS * :sasl=PLAIN,EXTERNAL\r\n" ++
            "CAP * LS * :sts=duration=604800\r\n" ++
            "CAP * LS :multiline\r\n",
        out.items,
    );
}

test "REQ parse accepts value-bearing requests" {
    var tokens: [4]RequestedToken = undefined;
    const requested = try parseReq(
        testRegistry(),
        .{ .values = &test_values },
        ":sasl=SCRAM-SHA-256 -sts multiline=max-lines=64",
        &tokens,
    );

    try std.testing.expectEqual(@as(usize, 3), requested.token_count);
    try std.testing.expect(requested.add.contains(.sasl));
    try std.testing.expect(requested.add.contains(.multiline));
    try std.testing.expect(requested.remove.contains(.sts));
    try std.testing.expectEqual(cap.CapId.sasl, tokens[0].id);
    try std.testing.expectEqualStrings("sasl", tokens[0].name);
    try std.testing.expectEqualStrings("SCRAM-SHA-256", tokens[0].value.?);
    try std.testing.expect(!tokens[0].remove);
    try std.testing.expectEqual(cap.CapId.sts, tokens[1].id);
    try std.testing.expect(tokens[1].remove);
    try std.testing.expectEqual(cap.CapId.multiline, tokens[2].id);
    try std.testing.expectEqualStrings("max-lines=64", tokens[2].value.?);
}

test "REQ parse rejects unsupported values and unvalued caps with values" {
    try std.testing.expectError(
        error.UnsupportedValue,
        parseReq(testRegistry(), .{ .values = &test_values }, "sasl=OAUTHBEARER", null),
    );
    try std.testing.expectError(
        error.UnsupportedValue,
        parseReq(testRegistry(), .{}, "server-time=on", null),
    );
}

test "REQ parse is atomic into returned sets" {
    var tokens: [2]RequestedToken = undefined;
    try std.testing.expectError(
        error.InvalidRequest,
        parseReq(testRegistry(), .{ .values = &test_values }, "sasl=PLAIN unknown-cap", &tokens),
    );
}
