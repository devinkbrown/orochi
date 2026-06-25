// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic property tests for the unified IRCv3 metadata / IRCX PROP store.
const std = @import("std");
const metadata = @import("metadata.zig");

const seed: u64 = 0x4d45_5441_5052_4f50;
const fuzz_iterations: usize = 1600;
const round_trip_iterations: usize = 700;
const validation_iterations: usize = 700;
const line_iterations: usize = 500;
const max_line_bytes: usize = 512;

const PropStore = metadata.MetadataStore(.{
    .max_entity_bytes = 32,
    .max_key_bytes = 32,
    .max_value_bytes = 320,
    .max_keys_per_entity = 64,
    .max_subscriptions = 8,
});

const LineError = error{
    InvalidWireToken,
    InvalidValue,
    OutputTooSmall,
};

test "metadata set get and clear are total over bounded attacker bytes" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x1001);
    const random = prng.random();

    var store = metadata.DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    var entity_buf: [metadata.default_max_entity_bytes + 16]u8 = undefined;
    var key_buf: [metadata.default_max_key_bytes + 16]u8 = undefined;
    var value_buf: [metadata.default_max_value_bytes + 16]u8 = undefined;

    for (0..fuzz_iterations) |iteration| {
        const entity = randomEntity(random, &entity_buf, iteration);
        const key = attackerSlice(random, &key_buf, iteration + 17);
        const value = attackerSlice(random, &value_buf, iteration + 41);

        if (store.set(entity, key, value, .public, .server)) |change| {
            try std.testing.expectEqual(entity.kind, change.entity.kind);
            try std.testing.expectEqualStrings(key, change.key);
            try std.testing.expectEqualStrings(value, change.value.?);
            try std.testing.expect(change.visibility == .public or change.visibility == .secret);
        } else |err| {
            try expectMetadataError(err);
        }

        if (store.get(entity, key, .server)) |maybe_entry| {
            if (maybe_entry) |entry| {
                try std.testing.expectEqual(entity.kind, entry.entity.kind);
                try std.testing.expectEqualStrings(key, entry.key);
            }
        } else |err| {
            try expectMetadataError(err);
        }

        if (store.clearKey(entity, key, .server)) |_| {} else |err| {
            try expectMetadataError(err);
        }
    }
}

test "key validation enforces metadata charset and length" {
    var max_key: [metadata.default_max_key_bytes]u8 = undefined;
    @memset(&max_key, 'a');
    try metadata.validateKey(&max_key);

    var too_long_key: [metadata.default_max_key_bytes + 1]u8 = undefined;
    @memset(&too_long_key, 'a');
    try std.testing.expectError(error.InvalidKey, metadata.validateKey(""));
    try std.testing.expectError(error.InvalidKey, metadata.validateKey(&too_long_key));

    const invalid = [_][]const u8{
        "BadKey",
        "bad key",
        "bad:key",
        "bad$key",
        "bad\rkey",
        "bad\nkey",
        "bad\x00key",
    };
    for (invalid) |key| {
        try std.testing.expectError(error.InvalidKey, metadata.validateKey(key));
    }

    var prng = std.Random.DefaultPrng.init(seed ^ 0x2002);
    const random = prng.random();
    var key_buf: [metadata.default_max_key_bytes + 16]u8 = undefined;

    for (0..validation_iterations) |iteration| {
        const key = attackerSlice(random, &key_buf, iteration);
        if (metadata.validateKey(key)) {
            try expectValidKeyBytes(key, metadata.default_max_key_bytes);
        } else |err| {
            try std.testing.expectEqual(error.InvalidKey, err);
        }
    }
}

test "entity and value limits are enforced without allocator leaks" {
    var store = metadata.DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    var max_value: [metadata.default_max_value_bytes]u8 = undefined;
    @memset(&max_value, 'v');
    var too_long_value: [metadata.default_max_value_bytes + 1]u8 = undefined;
    @memset(&too_long_value, 'w');

    const user = metadata.Entity{ .kind = .user, .name = "alice" };
    try metadata.validateEntity(user, metadata.default_max_entity_bytes);
    _ = try store.set(user, "status", &max_value, .public, .self);
    try std.testing.expectError(error.InvalidValue, store.set(user, "status", &too_long_value, .public, .self));
    try std.testing.expectError(error.InvalidValue, store.set(user, "status", "\xff", .public, .self));

    try std.testing.expectError(error.InvalidEntity, metadata.validateEntity(.{ .kind = .user, .name = "" }, metadata.default_max_entity_bytes));
    try std.testing.expectError(error.InvalidEntity, metadata.validateEntity(.{ .kind = .user, .name = "#not-user" }, metadata.default_max_entity_bytes));
    try std.testing.expectError(error.InvalidEntity, metadata.validateEntity(.{ .kind = .channel, .name = "not-channel" }, metadata.default_max_entity_bytes));
    try std.testing.expectError(error.InvalidEntity, metadata.validateEntity(.{ .kind = .channel, .name = "#bad\nchan" }, metadata.default_max_entity_bytes));

    var prng = std.Random.DefaultPrng.init(seed ^ 0x3003);
    const random = prng.random();
    var value_buf: [metadata.default_max_value_bytes + 16]u8 = undefined;

    for (0..validation_iterations) |iteration| {
        const value = attackerSlice(random, &value_buf, iteration);
        if (store.set(user, "fuzz", value, .public, .self)) |_| {
            try std.testing.expect(value.len <= metadata.default_max_value_bytes);
            try std.testing.expect(std.unicode.utf8ValidateSlice(value));
        } else |err| switch (err) {
            error.InvalidValue => {
                try std.testing.expect(value.len > metadata.default_max_value_bytes or !std.unicode.utf8ValidateSlice(value));
            },
            else => try expectMetadataError(err),
        }
    }
}

test "constructed metadata and PROP operations round trip through the same keys" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x4004);
    const random = prng.random();

    var store = PropStore.init(std.testing.allocator);
    defer store.deinit();

    var entity_buf: [32]u8 = undefined;
    var key_buf: [32]u8 = undefined;
    var value_buf: [160]u8 = undefined;
    var listed_buf: [8]metadata.EntryView = undefined;
    var props_buf: [8]metadata.PropView = undefined;

    for (0..round_trip_iterations) |iteration| {
        const entity = validEntity(random, &entity_buf, iteration);
        const key = validKey(random, &key_buf, iteration);
        const value = validValue(random, &value_buf, iteration);

        const change = try store.set(entity, key, value, .public, .server);
        try std.testing.expectEqualStrings(key, change.key);
        try std.testing.expectEqualStrings(value, change.value.?);

        const got = (try store.get(entity, key, .public)).?;
        try std.testing.expectEqualStrings(entity.name, got.entity.name);
        try std.testing.expectEqualStrings(key, got.key);
        try std.testing.expectEqualStrings(value, got.value);

        const listed = try store.list(entity, .public, &listed_buf);
        try std.testing.expect(listed.len >= 1);
        try expectListedEntry(listed, key, value);

        _ = try store.propSet(entity, "Topic", value, .server);
        const via_prop = (try store.propGet(entity, "topic", .public)).?;
        try std.testing.expectEqualStrings("Topic", via_prop.prop);
        try std.testing.expectEqualStrings(value, via_prop.entry.value);

        const props = try store.propList(entity, .public, &props_buf);
        try std.testing.expect(props.len >= 1);
        try std.testing.expect(try store.propClear(entity, "Topic", .server));

        try std.testing.expect(try store.clearKey(entity, key, .server));
        try std.testing.expectEqual(@as(?metadata.EntryView, null), try store.get(entity, key, .public));
    }
}

test "restricted keys and visibility remain permission gated" {
    var store = metadata.DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const room = metadata.Entity{ .kind = .channel, .name = "#ops" };
    try std.testing.expect(try store.isRestricted("ownerkey"));
    try std.testing.expectError(error.KeyRestricted, store.set(room, "ownerkey", "secret", .secret, .channel_admin));
    try std.testing.expectError(error.KeyRestricted, store.clearKey(room, "ownerkey", .channel_admin));

    _ = try store.set(room, "ownerkey", "secret", .secret, .server);
    try std.testing.expectError(error.NoPermission, store.get(room, "ownerkey", .server));

    _ = try store.set(room, "topic", "visible", .members, .channel_admin);
    try std.testing.expectError(error.NoPermission, store.get(room, "topic", .public));
    try std.testing.expect((try store.get(room, "topic", .member)) != null);
}

test "SET and batch response rendering stays bounded for generated store views" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x5005);
    const random = prng.random();

    var store = PropStore.init(std.testing.allocator);
    defer store.deinit();

    var entity_buf: [32]u8 = undefined;
    var key_buf: [32]u8 = undefined;
    var value_buf: [320]u8 = undefined;
    var line_buf: [max_line_bytes]u8 = undefined;

    for (0..line_iterations) |iteration| {
        const entity = validEntity(random, &entity_buf, iteration);
        const key = validKey(random, &key_buf, iteration);
        const value = validLineValue(random, &value_buf, iteration, entity.name.len, key.len);
        _ = try store.set(entity, key, value, .public, .server);

        const entry = (try store.get(entity, key, .public)).?;
        const set_line = try renderSetLine(entry, &line_buf);
        try expectLineBoundedAndTerminated(set_line);
        try expectNoEmbeddedCrLfNul(set_line[0 .. set_line.len - 2]);

        const open_line = try renderBatchLine('+', "mzmeta0000000001", &line_buf);
        try expectLineBoundedAndTerminated(open_line);
        const close_line = try renderBatchLine('-', "mzmeta0000000001", &line_buf);
        try expectLineBoundedAndTerminated(close_line);

        try std.testing.expect(try store.clearKey(entity, key, .server));
    }
}

test "wire response rendering rejects stored CR LF and NUL values" {
    var store = metadata.DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const entity = metadata.Entity{ .kind = .channel, .name = "#wire" };
    var line_buf: [max_line_bytes]u8 = undefined;

    const unsafe_values = [_][]const u8{
        "line\nbreak",
        "carriage\rreturn",
        "nul\x00byte",
    };

    for (unsafe_values) |value| {
        _ = try store.set(entity, "topic", value, .public, .server);
        const entry = (try store.get(entity, "topic", .public)).?;
        try std.testing.expectError(error.InvalidValue, renderSetLine(entry, &line_buf));
    }
}

fn expectMetadataError(err: metadata.MetadataError) !void {
    switch (err) {
        error.InvalidEntity,
        error.InvalidKey,
        error.InvalidValue,
        error.InvalidVisibility,
        error.KeyRestricted,
        error.KeyNotSet,
        error.LimitReached,
        error.TooManySubscriptions,
        error.NoPermission,
        error.OutputTooSmall,
        => {},
    }
}

fn attackerSlice(random: std.Random, buf: []u8, iteration: usize) []const u8 {
    const len = randomLength(random, iteration, buf.len);
    fillAttackerBytes(random, buf[0..len], iteration);
    return buf[0..len];
}

fn randomLength(random: std.Random, iteration: usize, max_len: usize) usize {
    return switch (iteration % 16) {
        0 => 0,
        1 => 1,
        2 => @min(max_len, metadata.default_max_key_bytes),
        3 => max_len,
        4 => if (max_len > 0) max_len - 1 else 0,
        else => random.uintLessThan(usize, max_len + 1),
    };
}

fn fillAttackerBytes(random: std.Random, out: []u8, iteration: usize) void {
    for (out, 0..) |*byte, index| {
        byte.* = switch ((iteration + index + random.uintLessThan(u8, 32)) % 24) {
            0 => 0,
            1 => '\r',
            2 => '\n',
            3 => ' ',
            4 => ':',
            5 => ',',
            6 => '#',
            7 => '&',
            8 => '$',
            9 => 0x7f,
            10 => 0x80,
            11 => 0xff,
            12...15 => 'A' + random.uintLessThan(u8, 26),
            16...20 => 'a' + random.uintLessThan(u8, 26),
            21 => '0' + random.uintLessThan(u8, 10),
            else => random.int(u8),
        };
    }
}

fn randomEntity(random: std.Random, buf: []u8, iteration: usize) metadata.Entity {
    const name = attackerSlice(random, buf, iteration);
    return .{
        .kind = if (random.boolean()) .channel else .user,
        .name = name,
    };
}

fn validEntity(random: std.Random, buf: []u8, iteration: usize) metadata.Entity {
    const channel = iteration % 2 == 0;
    const prefix: u8 = if (channel) '#' else 'u';
    const min_len: usize = if (channel) 2 else 1;
    const len = min_len + random.uintLessThan(usize, buf.len - min_len + 1);
    buf[0] = prefix;
    var index: usize = 1;
    while (index < len) : (index += 1) {
        buf[index] = switch (random.uintLessThan(u8, 8)) {
            0...3 => 'a' + random.uintLessThan(u8, 26),
            4...5 => '0' + random.uintLessThan(u8, 10),
            6 => '-',
            else => '_',
        };
    }
    return .{ .kind = if (channel) .channel else .user, .name = buf[0..len] };
}

fn validKey(random: std.Random, buf: []u8, iteration: usize) []const u8 {
    const len = 1 + random.uintLessThan(usize, buf.len);
    for (buf[0..len], 0..) |*byte, index| {
        byte.* = switch ((iteration + index + random.uintLessThan(u8, 8)) % 8) {
            0...2 => 'a' + random.uintLessThan(u8, 26),
            3...4 => '0' + random.uintLessThan(u8, 10),
            5 => '_',
            6 => '.',
            else => '-',
        };
    }
    return buf[0..len];
}

fn validValue(random: std.Random, buf: []u8, iteration: usize) []const u8 {
    const len = random.uintLessThan(usize, buf.len + 1);
    for (buf[0..len], 0..) |*byte, index| {
        byte.* = switch ((iteration + index + random.uintLessThan(u8, 12)) % 10) {
            0 => ' ',
            1...5 => 'a' + random.uintLessThan(u8, 26),
            6...7 => '0' + random.uintLessThan(u8, 10),
            8 => '.',
            else => '-',
        };
    }
    return buf[0..len];
}

fn validLineValue(
    random: std.Random,
    buf: []u8,
    iteration: usize,
    entity_len: usize,
    key_len: usize,
) []const u8 {
    const fixed = "METADATA ".len + " SET ".len + " ".len + " :".len + "\r\n".len +
        entity_len + key_len + metadata.Visibility.public.token().len;
    const max_value_len = @min(buf.len, max_line_bytes - fixed);
    const len = random.uintLessThan(usize, max_value_len + 1);
    for (buf[0..len], 0..) |*byte, index| {
        byte.* = switch ((iteration + index + random.uintLessThan(u8, 8)) % 8) {
            0...4 => 'a' + random.uintLessThan(u8, 26),
            5...6 => '0' + random.uintLessThan(u8, 10),
            else => '-',
        };
    }
    return buf[0..len];
}

fn expectValidKeyBytes(key: []const u8, max_len: usize) !void {
    try std.testing.expect(key.len > 0);
    try std.testing.expect(key.len <= max_len);
    for (key) |byte| {
        const ok = (byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or
            byte == '_' or byte == '.' or byte == '/' or byte == '-';
        try std.testing.expect(ok);
    }
}

fn expectListedEntry(entries: []const metadata.EntryView, key: []const u8, value: []const u8) !void {
    for (entries) |entry| {
        if (std.mem.eql(u8, key, entry.key)) {
            try std.testing.expectEqualStrings(value, entry.value);
            return;
        }
    }
    return error.KeyNotSet;
}

fn renderSetLine(entry: metadata.EntryView, out: []u8) LineError![]const u8 {
    try expectWireToken(entry.entity.name);
    try expectWireToken(entry.key);
    try expectWireToken(entry.ircv3VisibilityToken());
    try expectWireValue(entry.value);

    const line = std.fmt.bufPrint(
        out,
        "METADATA {s} SET {s} {s} :{s}\r\n",
        .{ entry.entity.name, entry.key, entry.ircv3VisibilityToken(), entry.value },
    ) catch return error.OutputTooSmall;
    if (line.len > max_line_bytes) return error.OutputTooSmall;
    return line;
}

fn renderBatchLine(prefix: u8, ref: []const u8, out: []u8) LineError![]const u8 {
    try expectWireToken(ref);
    const line = std.fmt.bufPrint(out, "BATCH {c}{s} metadata\r\n", .{ prefix, ref }) catch return error.OutputTooSmall;
    if (line.len > max_line_bytes) return error.OutputTooSmall;
    return line;
}

fn expectWireToken(token: []const u8) LineError!void {
    if (token.len == 0) return error.InvalidWireToken;
    for (token) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == '\r' or byte == '\n' or byte == 0) {
            return error.InvalidWireToken;
        }
    }
}

fn expectWireValue(value: []const u8) LineError!void {
    for (value) |byte| {
        if (byte == '\r' or byte == '\n' or byte == 0) return error.InvalidValue;
    }
}

fn expectLineBoundedAndTerminated(line: []const u8) !void {
    try std.testing.expect(line.len <= max_line_bytes);
    try std.testing.expect(std.mem.endsWith(u8, line, "\r\n"));
}

fn expectNoEmbeddedCrLfNul(line_body: []const u8) !void {
    try std.testing.expect(std.mem.indexOfScalar(u8, line_body, '\r') == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, line_body, '\n') == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, line_body, 0) == null);
}
