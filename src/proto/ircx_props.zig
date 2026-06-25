// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic property tests for the IRCX protocol model.
const std = @import("std");
const ircx = @import("ircx.zig");

const seed: u64 = 0x4952_4358_5052_4f50;
const parse_iterations: usize = 1600;
const enum_iterations: usize = 900;
const entity_iterations: usize = 900;
const property_iterations: usize = 500;
const access_iterations: usize = 500;

test "IRCX command line parser is total over attacker bytes" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x1001);
    const random = prng.random();
    var input_buf: [640]u8 = undefined;

    for (0..parse_iterations) |i| {
        const input = attackerSlice(random, &input_buf, i);
        const parsed = ircx.parseIrcxCommand(input) catch |err| {
            try expectParseIrcxError(err);
            continue;
        };

        try std.testing.expect(parsed == .ircx or parsed == .isircx);
    }
}

test "constructed IRCX commands parse and apply independent of case" {
    const commands = [_]struct {
        wire: []const u8,
        expected: ircx.IrcxCommand,
    }{
        .{ .wire = "IRCX", .expected = .ircx },
        .{ .wire = "ircx", .expected = .ircx },
        .{ .wire = "ISIRCX", .expected = .isircx },
        .{ .wire = "isircx trailing parameters", .expected = .isircx },
    };

    for (commands) |case| {
        var state = ircx.ClientIrcxState{};
        const parsed = try ircx.applyIrcxLine(&state, case.wire, 0x4000_0001);

        try std.testing.expectEqual(case.expected, parsed);
        try std.testing.expect(state.enabled);
        try std.testing.expect(state.namesx);
        try std.testing.expectEqual(@as(u64, 0x4000_0001), state.capability_mask);
    }
}

test "enum token parsers are total and valid tokens round trip" {
    inline for (.{ ircx.EntityScope.channel, ircx.EntityScope.user, ircx.EntityScope.account, ircx.EntityScope.member, ircx.EntityScope.onjoin, ircx.EntityScope.onpart, ircx.EntityScope.ownerkey, ircx.EntityScope.opkey }) |scope| {
        try std.testing.expectEqual(scope, ircx.EntityScope.parse(scope.token()).?);
    }

    inline for (.{ ircx.AccessLevel.voice, ircx.AccessLevel.host, ircx.AccessLevel.owner, ircx.AccessLevel.deny, ircx.AccessLevel.grant, ircx.AccessLevel.quiet }) |level| {
        try std.testing.expectEqual(level, ircx.AccessLevel.parse(level.token()).?);
    }

    try std.testing.expectEqual(ircx.AccessLevel.host, ircx.AccessLevel.parse("op").?);
    try std.testing.expectEqual(ircx.AccessLevel.owner, ircx.AccessLevel.parse("admin").?);
    try std.testing.expectEqual(ircx.IrcxCommand.ircx, ircx.IrcxCommand.parse("iRcX").?);
    try std.testing.expectEqual(ircx.IrcxCommand.isircx, ircx.IrcxCommand.parse("IsIrCx").?);

    var prng = std.Random.DefaultPrng.init(seed ^ 0x2002);
    const random = prng.random();
    var token_buf: [96]u8 = undefined;

    for (0..enum_iterations) |i| {
        const token = attackerSlice(random, &token_buf, i);

        if (ircx.IrcxCommand.parse(token)) |command| {
            try std.testing.expect(command == .ircx or command == .isircx);
        }
        if (ircx.EntityScope.parse(token)) |scope| {
            try std.testing.expectEqual(scope, ircx.EntityScope.parse(scope.token()).?);
        }
        if (ircx.AccessLevel.parse(token)) |level| {
            try std.testing.expectEqual(level, ircx.AccessLevel.parse(level.token()).?);
        }
    }
}

test "entity parser validates arbitrary bytes and returned ids stay in input" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x3003);
    const random = prng.random();
    var id_buf: [ircx.MAX_ENTITY_ID + 16]u8 = undefined;

    for (0..entity_iterations) |i| {
        const id = attackerSlice(random, &id_buf, i);
        for ([_]ircx.EntityScope{ .channel, .user, .account, .member, .onjoin, .onpart, .ownerkey, .opkey }) |scope| {
            const entity = ircx.Entity.init(scope, id) catch |err| {
                try std.testing.expectEqual(error.InvalidEntity, err);
                continue;
            };

            try std.testing.expectEqual(scope, entity.scope);
            try std.testing.expectEqualSlices(u8, id, entity.id);
            try expectSliceWithin(id, entity.id);
        }
    }
}

test "property keys and store operations round trip constructed values" {
    var store = ircx.PropertyStore.init(std.testing.allocator);
    defer store.deinit();

    var prng = std.Random.DefaultPrng.init(seed ^ 0x4004);
    const random = prng.random();
    var channel_buf: [ircx.MAX_ENTITY_ID]u8 = undefined;
    var name_buf: [ircx.MAX_PROP_NAME]u8 = undefined;
    var value_buf: [ircx.MAX_PROP_VALUE]u8 = undefined;
    var key_buf: [ircx.MAX_PROPERTY_KEY]u8 = undefined;
    var listed_buf: [8]ircx.PropertyView = undefined;

    for (0..property_iterations) |i| {
        const channel = validChannel(random, &channel_buf, i);
        const entity = try ircx.Entity.init(.channel, channel);
        const name = validPropertyName(random, &name_buf, i);
        const value = validPropertyValue(random, &value_buf, i);

        const key = try ircx.writePropertyKey(&key_buf, entity, name);
        try expectSliceWithin(&key_buf, key);
        try expectCanonicalPropertyKey(entity, name, key);

        try store.set(entity, name, value);
        const got = (try store.get(entity, name)).?;
        try std.testing.expectEqual(ircx.EntityScope.channel, got.entity.scope);
        try std.testing.expectEqualStrings(channel, got.entity.id);
        try std.testing.expectEqualStrings(name, got.name);
        try std.testing.expectEqualStrings(value, got.value);

        const listed = try store.list(entity, name, &listed_buf);
        try std.testing.expectEqual(@as(usize, 1), listed.len);
        try std.testing.expectEqualStrings(name, listed[0].name);
        try std.testing.expectEqualStrings(value, listed[0].value);
    }
}

test "property validation enforces name value entity and output limits" {
    const entity = try ircx.Entity.init(.channel, "#orochi");
    var store = ircx.PropertyStore.init(std.testing.allocator);
    defer store.deinit();

    var max_name: [ircx.MAX_PROP_NAME]u8 = undefined;
    @memset(&max_name, 'a');
    var too_long_name: [ircx.MAX_PROP_NAME + 1]u8 = undefined;
    @memset(&too_long_name, 'b');
    var max_value: [ircx.MAX_PROP_VALUE]u8 = undefined;
    @memset(&max_value, 'v');
    var too_long_value: [ircx.MAX_PROP_VALUE + 1]u8 = undefined;
    @memset(&too_long_value, 'w');

    try store.set(entity, &max_name, &max_value);
    try std.testing.expect((try store.get(entity, &max_name)) != null);
    try std.testing.expectError(error.InvalidPropertyName, store.set(entity, &too_long_name, ""));
    try std.testing.expectError(error.InvalidPropertyName, store.set(entity, "", ""));
    try std.testing.expectError(error.InvalidPropertyName, store.set(entity, "bad name", ""));
    try std.testing.expectError(error.InvalidPropertyName, store.set(entity, "bad:name", ""));
    try std.testing.expectError(error.InvalidPropertyValue, store.set(entity, "name", &too_long_value));
    try std.testing.expectError(error.InvalidPropertyValue, store.set(entity, "name", "line\nbreak"));
    try std.testing.expectError(error.OutputTooSmall, ircx.writePropertyKey(&[_]u8{}, entity, &max_name));

    try store.set(entity, "one", "1");
    try store.set(entity, "two", "2");
    var one_slot: [1]ircx.PropertyView = undefined;
    try std.testing.expectError(error.OutputTooSmall, store.list(entity, null, &one_slot));

    var too_long_entity: [ircx.MAX_ENTITY_ID + 1]u8 = undefined;
    @memset(&too_long_entity, 'a');
    too_long_entity[0] = '#';
    try std.testing.expectError(error.InvalidEntity, ircx.Entity.init(.channel, &too_long_entity));
}

test "property store methods are total over bounded attacker bytes" {
    var store = ircx.PropertyStore.init(std.testing.allocator);
    defer store.deinit();

    var prng = std.Random.DefaultPrng.init(seed ^ 0x5005);
    const random = prng.random();
    var id_buf: [ircx.MAX_ENTITY_ID + 8]u8 = undefined;
    var name_buf: [ircx.MAX_PROP_NAME + 8]u8 = undefined;
    var value_buf: [ircx.MAX_PROP_VALUE + 8]u8 = undefined;
    var out: [4]ircx.PropertyView = undefined;

    for (0..property_iterations) |i| {
        const scope = randomScope(random, i);
        const id = attackerSlice(random, &id_buf, i);
        const entity = ircx.Entity.init(scope, id) catch |err| {
            try std.testing.expectEqual(error.InvalidEntity, err);
            continue;
        };

        const name = attackerSlice(random, &name_buf, i + 13);
        const value = attackerSlice(random, &value_buf, i + 29);

        store.set(entity, name, value) catch |err| {
            try expectIrcxOrAllocError(err);
        };
        _ = store.get(entity, name) catch |err| {
            try expectIrcxOrAllocError(err);
        };
        _ = store.list(entity, name, &out) catch |err| {
            try expectIrcxOrAllocError(err);
        };
        _ = store.remove(entity, name) catch |err| {
            try expectIrcxOrAllocError(err);
        };
    }
}

test "ACCESS store round trips constructed masks and enforces limits" {
    var store = ircx.AccessStore.init(std.testing.allocator);
    defer store.deinit();

    var prng = std.Random.DefaultPrng.init(seed ^ 0x6006);
    const random = prng.random();
    var channel_buf: [ircx.MAX_ENTITY_ID]u8 = undefined;
    var mask_buf: [ircx.MAX_ACCESS_MASK]u8 = undefined;
    var listed_buf: [8]ircx.AccessEntryView = undefined;

    for (0..access_iterations) |i| {
        const channel = validChannel(random, &channel_buf, i);
        const mask = validAccessMask(random, &mask_buf, i);
        const level = randomAccessLevel(random, i);

        try store.add(channel, mask, level);
        const hit = (try store.matchHostmask(channel, mask)).?;
        try std.testing.expectEqual(level, hit.level);
        try std.testing.expectEqualStrings(channel, hit.channel);
        try std.testing.expectEqualStrings(mask, hit.mask);

        const listed = try store.list(channel, &listed_buf);
        try std.testing.expect(listed.len >= 1);
    }

    var max_mask: [ircx.MAX_ACCESS_MASK]u8 = undefined;
    @memset(&max_mask, 'm');
    try store.add("#chan", &max_mask, .voice);

    var too_long_mask: [ircx.MAX_ACCESS_MASK + 1]u8 = undefined;
    @memset(&too_long_mask, 'm');
    try std.testing.expectError(error.InvalidAccessMask, store.add("#chan", &too_long_mask, .voice));
    try std.testing.expectError(error.InvalidAccessMask, store.add("#chan", "", .voice));
    try std.testing.expectError(error.InvalidAccessMask, store.add("#chan", "bad mask", .voice));
    try std.testing.expectError(error.InvalidEntity, store.add("not-channel", "mask", .voice));

    var zero_slots: [0]ircx.AccessEntryView = .{};
    try std.testing.expectError(error.OutputTooSmall, store.list("#chan", &zero_slots));
}

test "ACCESS store methods are total over bounded attacker bytes" {
    var store = ircx.AccessStore.init(std.testing.allocator);
    defer store.deinit();

    var prng = std.Random.DefaultPrng.init(seed ^ 0x7007);
    const random = prng.random();
    var channel_buf: [ircx.MAX_ENTITY_ID + 8]u8 = undefined;
    var mask_buf: [ircx.MAX_ACCESS_MASK + 8]u8 = undefined;
    var out: [4]ircx.AccessEntryView = undefined;

    for (0..access_iterations) |i| {
        const channel = attackerSlice(random, &channel_buf, i);
        const mask = attackerSlice(random, &mask_buf, i + 19);
        const level = randomAccessLevel(random, i);

        store.add(channel, mask, level) catch |err| {
            try expectIrcxOrAllocError(err);
        };
        _ = store.matchHostmask(channel, mask) catch |err| {
            try expectIrcxOrAllocError(err);
        };
        _ = store.list(channel, &out) catch |err| {
            try expectIrcxOrAllocError(err);
        };
        _ = store.remove(channel, mask) catch |err| {
            try expectIrcxOrAllocError(err);
        };
    }
}

test "advertisement writer and numeric lookup are bounded and deterministic" {
    var out: [96]u8 = undefined;
    const rendered = try ircx.writeAdvertiseTokens(&out, .{
        .max_codepage = 1,
        .max_language = 2,
        .max_prop = ircx.MAX_PROP_VALUE,
        .max_access = ircx.MAX_ACCESS_MASK,
    });
    try expectSliceWithin(&out, rendered);
    try std.testing.expectEqualStrings("IRCX MAXCODEPAGE=1 MAXLANGUAGE=2 MAXPROP=512 MAXACCESS=128", rendered);
    try std.testing.expectError(error.OutputTooSmall, ircx.writeAdvertiseTokens(out[0..8], .{}));

    for (ircx.numeric_replies) |reply| {
        const found = ircx.numericByCode(reply.code).?;
        try std.testing.expectEqual(reply.code, found.code);
        try std.testing.expectEqualStrings(reply.name, found.name);
        try std.testing.expectEqualStrings(reply.text, found.text);
    }

    try std.testing.expectEqual(@as(?ircx.NumericReply, null), ircx.numericByCode(999));
}

fn attackerSlice(random: std.Random, buf: []u8, iteration: usize) []const u8 {
    const len = variedLen(random, iteration, buf.len);
    fillAttackerBytes(random, buf[0..len]);
    return buf[0..len];
}

fn variedLen(random: std.Random, iteration: usize, max_len: usize) usize {
    return switch (iteration % 19) {
        0 => 0,
        1 => 1,
        2 => @min(max_len, 2),
        3 => @min(max_len, 15),
        4 => @min(max_len, 64),
        5 => max_len,
        else => random.uintLessThan(usize, max_len + 1),
    };
}

fn fillAttackerBytes(random: std.Random, out: []u8) void {
    for (out) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 30)) {
            0 => 0,
            1 => '\r',
            2 => '\n',
            3 => '\t',
            4 => ' ',
            5 => ':',
            6 => ',',
            7 => '*',
            8 => '?',
            9 => '#',
            10 => '&',
            11 => '+',
            12 => '%',
            13 => '!',
            14 => '@',
            15 => 0x7f,
            16 => 0x80,
            17 => 0xff,
            18 => random.uintLessThan(u8, 0x20),
            19...22 => 'A' + random.uintLessThan(u8, 26),
            23...26 => 'a' + random.uintLessThan(u8, 26),
            27...28 => '0' + random.uintLessThan(u8, 10),
            else => random.int(u8),
        };
    }
}

fn validChannel(random: std.Random, buf: []u8, iteration: usize) []const u8 {
    const prefixes = [_]u8{ '#', '&', '%', '+' };
    const len = 2 + random.uintLessThan(usize, @min(buf.len, 32) - 1);
    buf[0] = prefixes[(iteration + random.uintLessThan(usize, prefixes.len)) % prefixes.len];
    fillSafeAtom(random, buf[1..len], true);
    return buf[0..len];
}

fn validPropertyName(random: std.Random, buf: []u8, iteration: usize) []const u8 {
    const len = switch (iteration % 11) {
        0 => 1,
        1 => ircx.MAX_PROP_NAME,
        else => 1 + random.uintLessThan(usize, @min(buf.len, 32)),
    };
    for (buf[0..len]) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 6)) {
            0 => 'A' + random.uintLessThan(u8, 26),
            1 => 'a' + random.uintLessThan(u8, 26),
            2 => '0' + random.uintLessThan(u8, 10),
            3 => '_',
            4 => '-',
            else => '.',
        };
    }
    return buf[0..len];
}

fn validPropertyValue(random: std.Random, buf: []u8, iteration: usize) []const u8 {
    const len = switch (iteration % 13) {
        0 => 0,
        1 => ircx.MAX_PROP_VALUE,
        else => random.uintLessThan(usize, @min(buf.len, 96) + 1),
    };
    fillSafeText(random, buf[0..len]);
    return buf[0..len];
}

fn validAccessMask(random: std.Random, buf: []u8, iteration: usize) []const u8 {
    const len = switch (iteration % 13) {
        0 => 1,
        1 => ircx.MAX_ACCESS_MASK,
        else => 1 + random.uintLessThan(usize, @min(buf.len, 48)),
    };
    fillSafeAtom(random, buf[0..len], false);
    return buf[0..len];
}

fn fillSafeAtom(random: std.Random, out: []u8, allow_channel_prefixes: bool) void {
    for (out) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 12)) {
            0 => 'A' + random.uintLessThan(u8, 26),
            1 => 'a' + random.uintLessThan(u8, 26),
            2 => '0' + random.uintLessThan(u8, 10),
            3 => '-',
            4 => '_',
            5 => '.',
            6 => '!',
            7 => '@',
            8 => '*',
            9 => '?',
            10 => if (allow_channel_prefixes) '#' else '~',
            else => '~',
        };
    }
}

fn fillSafeText(random: std.Random, out: []u8) void {
    for (out) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 16)) {
            0 => ' ',
            1 => ':',
            2 => ',',
            3 => 0x80,
            4 => 0xff,
            5 => '\t',
            6...9 => 'A' + random.uintLessThan(u8, 26),
            10...13 => 'a' + random.uintLessThan(u8, 26),
            else => '0' + random.uintLessThan(u8, 10),
        };
    }
}

fn randomScope(random: std.Random, iteration: usize) ircx.EntityScope {
    const scopes = [_]ircx.EntityScope{ .channel, .user, .account, .member, .onjoin, .onpart, .ownerkey, .opkey };
    return scopes[(iteration + random.uintLessThan(usize, scopes.len)) % scopes.len];
}

fn randomAccessLevel(random: std.Random, iteration: usize) ircx.AccessLevel {
    const levels = [_]ircx.AccessLevel{ .voice, .host, .owner, .deny, .grant, .quiet };
    return levels[(iteration + random.uintLessThan(usize, levels.len)) % levels.len];
}

fn expectCanonicalPropertyKey(entity: ircx.Entity, name: []const u8, key: []const u8) !void {
    var expected: [ircx.MAX_PROPERTY_KEY]u8 = undefined;
    const scope = entity.scope.token();
    var pos: usize = 0;

    copyLower(expected[pos .. pos + scope.len], scope);
    pos += scope.len;
    expected[pos] = 0x1f;
    pos += 1;
    copyLower(expected[pos .. pos + entity.id.len], entity.id);
    pos += entity.id.len;
    expected[pos] = 0x1f;
    pos += 1;
    copyLower(expected[pos .. pos + name.len], name);
    pos += name.len;

    try std.testing.expectEqualSlices(u8, expected[0..pos], key);
}

fn copyLower(dst: []u8, src: []const u8) void {
    for (src, 0..) |byte, i| dst[i] = std.ascii.toLower(byte);
}

fn expectSliceWithin(input: []const u8, slice: []const u8) !void {
    const input_start = @intFromPtr(input.ptr);
    const input_end = input_start + input.len;
    const slice_start = @intFromPtr(slice.ptr);
    const slice_end = slice_start + slice.len;

    try std.testing.expect(slice_start >= input_start);
    try std.testing.expect(slice_start <= input_end);
    try std.testing.expect(slice_end >= slice_start);
    try std.testing.expect(slice_end <= input_end);
}

fn expectParseIrcxError(err: ircx.ParseIrcxError) !void {
    switch (err) {
        error.EmptyLine,
        error.OversizeLine,
        error.EmbeddedNul,
        error.EmbeddedLineBreak,
        error.MissingCommand,
        error.MalformedPrefix,
        error.MalformedTags,
        error.TooManyParams,
        error.TooManyTags,
        error.UnknownIrcxCommand,
        => {},
    }
}

fn expectIrcxOrAllocError(err: anyerror) !void {
    switch (err) {
        error.InvalidEntity,
        error.InvalidPropertyName,
        error.InvalidPropertyValue,
        error.InvalidAccessMask,
        error.InvalidAccessLevel,
        error.OutputTooSmall,
        error.OutOfMemory,
        => {},
        else => return err,
    }
}
