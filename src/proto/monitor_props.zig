// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic property tests for IRCv3 MONITOR state handling.
const std = @import("std");
const monitor = @import("monitor.zig");

const seed: u64 = 0x4d4f_4e49_544f_5216;
const parse_iterations: usize = 4000;
const set_iterations: usize = 1400;
const notification_iterations: usize = 900;
const capacity_iterations: usize = 700;

const TestSink = struct {
    replies: [512]monitor.MonitorReply = undefined,
    storage: [32768]u8 = undefined,
    sink: monitor.MonitorReplySink = undefined,

    fn init(self: *TestSink) void {
        self.sink = .{ .replies = &self.replies, .storage = &self.storage };
    }

    fn reset(self: *TestSink) void {
        self.sink.count = 0;
        self.sink.used = 0;
    }
};

const ExpectedSet = struct {
    items: [32][monitor.MAX_NICK_BYTES]u8 = undefined,
    lens: [32]usize = undefined,
    count: usize = 0,

    fn contains(self: *const ExpectedSet, target: []const u8) bool {
        var lowered: [monitor.MAX_NICK_BYTES]u8 = undefined;
        const normalized = normalizeTarget(target, &lowered);
        return self.indexOf(normalized) != null;
    }

    fn add(self: *ExpectedSet, target: []const u8, capacity: usize) bool {
        var lowered: [monitor.MAX_NICK_BYTES]u8 = undefined;
        const normalized = normalizeTarget(target, &lowered);
        if (self.indexOf(normalized) != null) return true;
        if (self.count >= capacity) return false;

        @memcpy(self.items[self.count][0..normalized.len], normalized);
        self.lens[self.count] = normalized.len;
        self.count += 1;
        return true;
    }

    fn remove(self: *ExpectedSet, target: []const u8) void {
        var lowered: [monitor.MAX_NICK_BYTES]u8 = undefined;
        const normalized = normalizeTarget(target, &lowered);
        const index = self.indexOf(normalized) orelse return;

        const last = self.count - 1;
        if (index != last) {
            @memcpy(self.items[index][0..self.lens[last]], self.items[last][0..self.lens[last]]);
            self.lens[index] = self.lens[last];
        }
        self.count -= 1;
    }

    fn indexOf(self: *const ExpectedSet, normalized: []const u8) ?usize {
        for (0..self.count) |index| {
            if (std.mem.eql(u8, self.items[index][0..self.lens[index]], normalized)) return index;
        }
        return null;
    }
};

test "MONITOR subcommand and parameter parsing is total over attacker bytes" {
    inline for (.{ "+", "-", "C", "L", "S", "c", "l", "s" }) |token| {
        _ = try monitor.parseSubcommand(token);
    }

    var prng = std.Random.DefaultPrng.init(seed ^ 0x1001);
    const random = prng.random();
    var command_buf: [96]u8 = undefined;
    var target_buf: [160]u8 = undefined;

    for (0..parse_iterations) |iteration| {
        const command = attackerSlice(random, &command_buf, iteration);
        if (monitor.parseSubcommand(command)) |parsed| {
            try expectCanonicalSubcommand(command, parsed);
        } else |err| {
            try expectMonitorError(err);
        }

        var store = monitor.MonitorStore.init(std.testing.allocator, 12);
        defer store.deinit();

        var sink_data: TestSink = undefined;
        sink_data.init();

        const target = attackerSlice(random, &target_buf, iteration + 17);
        const params = [_][]const u8{ command, target };
        if (store.handle(1, &params, &sink_data.sink)) |_| {
            try std.testing.expect(store.monitorCount(1) <= 12);
        } else |err| {
            try expectMonitorError(err);
            try std.testing.expect(store.monitorCount(1) <= 12);
        }
    }
}

test "add remove operations keep monitor set consistent with reference model" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x2002);
    const random = prng.random();
    var store = monitor.MonitorStore.init(std.testing.allocator, 24);
    defer store.deinit();

    var sink_data: TestSink = undefined;
    sink_data.init();
    var expected = ExpectedSet{};

    var names: [32][monitor.MAX_NICK_BYTES]u8 = undefined;
    var lens: [names.len]usize = undefined;
    fillNameCorpus(random, &names, &lens);

    for (0..set_iterations) |iteration| {
        sink_data.reset();
        const index = random.uintLessThan(usize, names.len);
        const target = names[index][0..lens[index]];

        if (iteration % 3 == 0) {
            try store.removeTargets(5, target);
            expected.remove(target);
        } else {
            try store.addTargets(5, target, &sink_data.sink);
            _ = expected.add(target, 24);
        }

        try std.testing.expectEqual(expected.count, store.monitorCount(5));
        for (0..names.len) |name_index| {
            const candidate = names[name_index][0..lens[name_index]];
            try std.testing.expectEqual(expected.contains(candidate), try store.isMonitoring(5, candidate));
        }
    }
}

test "duplicate adds are idempotent and preserve target count" {
    var store = monitor.MonitorStore.init(std.testing.allocator, 8);
    defer store.deinit();

    var sink_data: TestSink = undefined;
    sink_data.init();

    try store.addTargets(9, "Alice", &sink_data.sink);
    try std.testing.expectEqual(@as(usize, 1), store.monitorCount(9));
    try std.testing.expectEqual(@as(usize, 1), sink_data.sink.count);

    sink_data.reset();
    try store.addTargets(9, "alice", &sink_data.sink);
    try store.addTargets(9, "ALICE", &sink_data.sink);
    try std.testing.expectEqual(@as(usize, 1), store.monitorCount(9));
    try std.testing.expectEqual(@as(usize, 0), sink_data.sink.count);
    try std.testing.expect(try store.isMonitoring(9, "aLiCe"));
}

test "monitor list respects capacity limit and does not overflow" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x3003);
    const random = prng.random();
    var names: [32][monitor.MAX_NICK_BYTES]u8 = undefined;
    var lens: [names.len]usize = undefined;
    fillNameCorpus(random, &names, &lens);

    for (0..capacity_iterations) |iteration| {
        const capacity = 1 + (iteration % 10);
        var store = monitor.MonitorStore.init(std.testing.allocator, capacity);
        defer store.deinit();

        var sink_data: TestSink = undefined;
        sink_data.init();

        var expected = ExpectedSet{};
        for (0..names.len) |index| {
            const target = names[(index + iteration) % names.len][0..lens[(index + iteration) % names.len]];
            sink_data.reset();
            try store.addTargets(11, target, &sink_data.sink);
            _ = expected.add(target, capacity);

            try std.testing.expectEqual(expected.count, store.monitorCount(11));
            try std.testing.expect(store.monitorCount(11) <= capacity);
        }

        sink_data.reset();
        try store.handle(11, &.{"L"}, &sink_data.sink);
        try std.testing.expectEqual(monitor.MonitorNumeric.RPL_ENDOFMONLIST, sink_data.sink.replies[sink_data.sink.count - 1].numeric);
        try expectListedTargetCount(expected.count, sink_data.sink.slice());
    }
}

test "online offline notification selection matches watched nick set" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x4004);
    const random = prng.random();
    var names: [32][monitor.MAX_NICK_BYTES]u8 = undefined;
    var lens: [names.len]usize = undefined;
    fillNameCorpus(random, &names, &lens);

    for (0..notification_iterations) |iteration| {
        var store = monitor.MonitorStore.init(std.testing.allocator, names.len);
        defer store.deinit();

        var sink_data: TestSink = undefined;
        sink_data.init();

        var watched: [8]bool = @splat(false);
        for (0..watched.len) |client_offset| {
            if (((iteration + client_offset) % 3) == 0 or random.boolean()) {
                watched[client_offset] = true;
                const client: monitor.ClientId = @intCast(client_offset + 1);
                try store.addTargets(client, names[iteration % names.len][0..lens[iteration % names.len]], &sink_data.sink);
            } else {
                const other = (iteration + client_offset + 1) % names.len;
                const client: monitor.ClientId = @intCast(client_offset + 1);
                try store.addTargets(client, names[other][0..lens[other]], &sink_data.sink);
            }
        }

        const target = names[iteration % names.len][0..lens[iteration % names.len]];
        sink_data.reset();
        try store.setOnline(target, &sink_data.sink);
        try expectNotificationClients(.RPL_MONONLINE, target, watched, sink_data.sink.slice());

        sink_data.reset();
        try store.setOnline(target, &sink_data.sink);
        try std.testing.expectEqual(@as(usize, 0), sink_data.sink.count);

        sink_data.reset();
        try store.setOffline(target, &sink_data.sink);
        try expectNotificationClients(.RPL_MONOFFLINE, target, watched, sink_data.sink.slice());

        sink_data.reset();
        try store.setOffline(target, &sink_data.sink);
        try std.testing.expectEqual(@as(usize, 0), sink_data.sink.count);
    }
}

fn expectMonitorError(err: monitor.MonitorError) !void {
    switch (err) {
        error.InvalidSubcommand,
        error.MissingParameter,
        error.InvalidTarget,
        error.OutputTooSmall,
        error.TooManyReplies,
        error.OutOfMemory,
        => {},
    }
}

fn expectCanonicalSubcommand(token: []const u8, parsed: monitor.MonitorSubcommand) !void {
    try std.testing.expectEqual(@as(usize, 1), token.len);
    switch (parsed) {
        .add => try std.testing.expectEqual(@as(u8, '+'), token[0]),
        .remove => try std.testing.expectEqual(@as(u8, '-'), token[0]),
        .clear => try std.testing.expect(token[0] == 'C' or token[0] == 'c'),
        .list => try std.testing.expect(token[0] == 'L' or token[0] == 'l'),
        .status => try std.testing.expect(token[0] == 'S' or token[0] == 's'),
    }
}

fn expectListedTargetCount(expected: usize, replies: []const monitor.MonitorReply) !void {
    var seen: usize = 0;
    for (replies) |reply| {
        switch (reply.numeric) {
            .RPL_MONLIST => seen += countCsvTargets(reply.targets),
            .RPL_ENDOFMONLIST => {},
            else => return error.UnexpectedReply,
        }
    }
    try std.testing.expectEqual(expected, seen);
}

fn expectNotificationClients(
    numeric: monitor.MonitorNumeric,
    target: []const u8,
    watched: [8]bool,
    replies: []const monitor.MonitorReply,
) !void {
    var seen: [watched.len]bool = @splat(false);
    var expected_count: usize = 0;
    for (watched) |is_watching| {
        if (is_watching) expected_count += 1;
    }

    try std.testing.expectEqual(expected_count, replies.len);
    for (replies) |reply| {
        try std.testing.expectEqual(numeric, reply.numeric);
        try std.testing.expectEqualStrings(target, reply.targets);
        try std.testing.expect(reply.client >= 1 and reply.client <= watched.len);

        const index: usize = @intCast(reply.client - 1);
        try std.testing.expect(watched[index]);
        try std.testing.expect(!seen[index]);
        seen[index] = true;
    }
}

fn countCsvTargets(targets: []const u8) usize {
    if (targets.len == 0) return 0;
    var count: usize = 1;
    for (targets) |ch| {
        if (ch == ',') count += 1;
    }
    return count;
}

fn attackerSlice(random: std.Random, buf: []u8, iteration: usize) []const u8 {
    const len = randomLength(random, iteration, buf.len);
    fillBiasedBytes(random, buf[0..len]);
    return buf[0..len];
}

fn randomLength(random: std.Random, iteration: usize, max_len: usize) usize {
    return switch (iteration % 18) {
        0 => 0,
        1 => 1,
        2 => @min(max_len, monitor.MAX_NICK_BYTES),
        3 => @min(max_len, monitor.MAX_NICK_BYTES + 1),
        4 => max_len,
        else => random.uintLessThan(usize, max_len + 1),
    };
}

fn fillBiasedBytes(random: std.Random, out: []u8) void {
    for (out) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 28)) {
            0 => '+',
            1 => '-',
            2 => 'C',
            3 => 'L',
            4 => 'S',
            5 => 'c',
            6 => 'l',
            7 => 's',
            8 => ',',
            9 => ':',
            10 => ' ',
            11 => '\t',
            12 => '\r',
            13 => '\n',
            14 => 0,
            15 => 0xff,
            16...20 => 'A' + random.uintLessThan(u8, 26),
            21...24 => 'a' + random.uintLessThan(u8, 26),
            else => random.int(u8),
        };
    }
}

fn fillNameCorpus(random: std.Random, names: *[32][monitor.MAX_NICK_BYTES]u8, lens: *[32]usize) void {
    for (0..names.len) |index| {
        const len = 1 + random.uintLessThan(usize, 14);
        lens[index] = len;
        for (names[index][0..len], 0..) |*byte, byte_index| {
            byte.* = if (byte_index == 0)
                'A' + @as(u8, @intCast((index + byte_index) % 26))
            else switch (random.uintLessThan(u8, 5)) {
                0 => 'A' + random.uintLessThan(u8, 26),
                1 => 'a' + random.uintLessThan(u8, 26),
                2 => '0' + random.uintLessThan(u8, 10),
                3 => '_',
                else => '-',
            };
        }
    }
}

fn normalizeTarget(target: []const u8, out: *[monitor.MAX_NICK_BYTES]u8) []const u8 {
    for (target, 0..) |ch, index| {
        out[index] = asciiLower(ch);
    }
    return out[0..target.len];
}

fn asciiLower(ch: u8) u8 {
    return if (ch >= 'A' and ch <= 'Z') ch + ('a' - 'A') else ch;
}
