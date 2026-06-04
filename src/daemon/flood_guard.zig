//! Deterministic per-client flood classification.
//!
//! This layer consumes the token-bucket and excess-flood primitives in
//! `flood.zig` and adds command-rate and target-change checks. It owns no
//! allocator, reads no clocks, and keeps only bounded per-connection state.
const std = @import("std");
const flood = @import("flood.zig");

pub const Decision = flood.FloodDecision;

pub const GuardParams = struct {
    messages: flood.BucketParams,
    bytes: flood.BucketParams,
    commands: flood.BucketParams,
    target_changes: flood.BucketParams,
    excess: flood.ExcessParams,
    throttle_penalty: u64 = 1,
    target_change_penalty: u64 = 1,
    max_tracked_targets: usize = 16,
};

pub const ParsedLine = struct {
    command: []const u8,
    first_param: []const u8 = "",
    byte_count: u64,
};

pub fn FloodGuard(comptime params: GuardParams) type {
    comptime validateGuardParams(params);

    return struct {
        const Self = @This();
        const MessageBucket = flood.TokenBucket(params.messages);
        const ByteBucket = flood.TokenBucket(params.bytes);
        const CommandBucket = flood.TokenBucket(params.commands);
        const TargetChangeBucket = flood.TokenBucket(params.target_changes);
        const Excess = flood.ExcessAccumulator(params.excess);

        message_rate: MessageBucket,
        byte_rate: ByteBucket,
        command_rate: CommandBucket,
        target_change_rate: TargetChangeBucket,
        excess_flood: Excess,
        targets: [params.max_tracked_targets]TargetKey = [_]TargetKey{TargetKey.empty} ** params.max_tracked_targets,
        target_count: usize = 0,
        next_target_slot: usize = 0,

        pub const Snapshot = struct {
            message_tokens: u64,
            byte_tokens: u64,
            command_tokens: u64,
            target_change_tokens: u64,
            excess_points: u64,
            tracked_targets: usize,
        };

        pub fn init(now_ms: i64) Self {
            return .{
                .message_rate = MessageBucket.init(now_ms),
                .byte_rate = ByteBucket.init(now_ms),
                .command_rate = CommandBucket.init(now_ms),
                .target_change_rate = TargetChangeBucket.init(now_ms),
                .excess_flood = Excess.init(now_ms),
            };
        }

        pub fn classifyRaw(self: *Self, now_ms: i64, raw_line: []const u8) Decision {
            return self.classifyParsed(now_ms, parseRaw(raw_line));
        }

        pub fn classifyParsed(self: *Self, now_ms: i64, line: ParsedLine) Decision {
            const message_ok = self.message_rate.tryConsume(now_ms, 1);
            const bytes_ok = self.byte_rate.tryConsume(now_ms, line.byte_count);
            const command_ok = self.command_rate.tryConsume(now_ms, 1);
            const target_ok = self.classifyTargetChange(now_ms, line);

            if (message_ok and bytes_ok and command_ok and target_ok) {
                self.excess_flood.decay(now_ms);
                if (self.excess_flood.tripped()) return .disconnect;
                return .allow;
            }

            const penalty = if (!target_ok) params.target_change_penalty else params.throttle_penalty;
            return self.excess_flood.add(now_ms, penalty);
        }

        pub fn decay(self: *Self, now_ms: i64) void {
            self.message_rate.refill(now_ms);
            self.byte_rate.refill(now_ms);
            self.command_rate.refill(now_ms);
            self.target_change_rate.refill(now_ms);
            self.excess_flood.decay(now_ms);
        }

        pub fn snapshot(self: *const Self) Snapshot {
            return .{
                .message_tokens = self.message_rate.available(),
                .byte_tokens = self.byte_rate.available(),
                .command_tokens = self.command_rate.available(),
                .target_change_tokens = self.target_change_rate.available(),
                .excess_points = self.excess_flood.current(),
                .tracked_targets = self.target_count,
            };
        }

        fn classifyTargetChange(self: *Self, now_ms: i64, line: ParsedLine) bool {
            if (!std.ascii.eqlIgnoreCase(line.command, "PRIVMSG")) return true;
            if (line.first_param.len == 0) return true;

            const key = TargetKey.init(line.first_param);
            if (self.hasTarget(key)) return true;
            if (!self.target_change_rate.tryConsume(now_ms, 1)) return false;
            self.rememberTarget(key);
            return true;
        }

        fn hasTarget(self: *const Self, key: TargetKey) bool {
            for (self.targets[0..self.target_count]) |target| {
                if (target.eql(key)) return true;
            }
            return false;
        }

        fn rememberTarget(self: *Self, key: TargetKey) void {
            if (self.target_count < self.targets.len) {
                self.targets[self.target_count] = key;
                self.target_count += 1;
                return;
            }

            self.targets[self.next_target_slot] = key;
            self.next_target_slot = (self.next_target_slot + 1) % self.targets.len;
        }
    };
}

fn validateGuardParams(comptime params: GuardParams) void {
    if (params.throttle_penalty == 0) @compileError("throttle penalty must be non-zero");
    if (params.target_change_penalty == 0) @compileError("target-change penalty must be non-zero");
    if (params.max_tracked_targets == 0) @compileError("target tracking must have at least one slot");
    _ = flood.TokenBucket(params.messages);
    _ = flood.TokenBucket(params.bytes);
    _ = flood.TokenBucket(params.commands);
    _ = flood.TokenBucket(params.target_changes);
    _ = flood.ExcessAccumulator(params.excess);
}

fn parseRaw(raw_line: []const u8) ParsedLine {
    const body = trimLineEnding(raw_line);
    var cursor = skipSpaces(body, 0);

    if (cursor < body.len and body[cursor] == '@') {
        cursor = skipSpaces(body, findSpace(body, cursor) orelse body.len);
    }
    if (cursor < body.len and body[cursor] == ':') {
        cursor = skipSpaces(body, findSpace(body, cursor) orelse body.len);
    }

    const command_start = cursor;
    const command_end = findSpace(body, cursor) orelse body.len;
    cursor = skipSpaces(body, command_end);

    var first_param: []const u8 = "";
    if (cursor < body.len) {
        if (body[cursor] == ':') {
            first_param = body[cursor + 1 ..];
        } else {
            const param_end = findSpace(body, cursor) orelse body.len;
            first_param = body[cursor..param_end];
        }
    }

    return .{
        .command = body[command_start..command_end],
        .first_param = first_param,
        .byte_count = @intCast(raw_line.len),
    };
}

fn trimLineEnding(input: []const u8) []const u8 {
    if (input.len >= 2 and input[input.len - 2] == '\r' and input[input.len - 1] == '\n') {
        return input[0 .. input.len - 2];
    }
    if (input.len >= 1 and (input[input.len - 1] == '\r' or input[input.len - 1] == '\n')) {
        return input[0 .. input.len - 1];
    }
    return input;
}

fn skipSpaces(input: []const u8, start: usize) usize {
    var cursor = start;
    while (cursor < input.len and input[cursor] == ' ') : (cursor += 1) {}
    return cursor;
}

fn findSpace(input: []const u8, start: usize) ?usize {
    var cursor = start;
    while (cursor < input.len) : (cursor += 1) {
        if (input[cursor] == ' ') return cursor;
    }
    return null;
}

const TargetKey = struct {
    hash: u64,
    len: usize,

    const empty: TargetKey = .{ .hash = 0, .len = 0 };

    fn init(target: []const u8) TargetKey {
        return .{ .hash = hashFoldedAscii(target), .len = target.len };
    }

    fn eql(self: TargetKey, other: TargetKey) bool {
        return self.hash == other.hash and self.len == other.len;
    }
};

fn hashFoldedAscii(input: []const u8) u64 {
    var hash: u64 = 0xcbf29ce484222325;
    for (input) |byte| {
        hash ^= asciiLower(byte);
        hash *%= 0x100000001b3;
    }
    return hash;
}

fn asciiLower(byte: u8) u8 {
    if (byte >= 'A' and byte <= 'Z') return byte + ('a' - 'A');
    return byte;
}

const TestGuard = FloodGuard(.{
    .messages = .{ .capacity = 2, .refill_tokens = 1, .refill_period_ms = 1000 },
    .bytes = .{ .capacity = 256, .refill_tokens = 256, .refill_period_ms = 1000 },
    .commands = .{ .capacity = 2, .refill_tokens = 1, .refill_period_ms = 1000 },
    .target_changes = .{ .capacity = 8, .refill_tokens = 8, .refill_period_ms = 1000 },
    .excess = .{ .threshold = 10, .decay_points = 1, .decay_period_ms = 1000 },
    .max_tracked_targets = 8,
});

test "burst then throttle then recover" {
    const allocator = std.testing.allocator;
    var guard = TestGuard.init(0);

    const line = try std.fmt.allocPrint(allocator, "PING :{s}\r\n", .{"mizuchi"});
    defer allocator.free(line);

    try std.testing.expectEqual(Decision.allow, guard.classifyRaw(0, line));
    try std.testing.expectEqual(Decision.allow, guard.classifyRaw(0, line));
    try std.testing.expectEqual(Decision.throttle, guard.classifyRaw(0, line));
    try std.testing.expectEqual(Decision.allow, guard.classifyRaw(1000, line));
}

test "distinct-target throttle" {
    const allocator = std.testing.allocator;
    const Guard = FloodGuard(.{
        .messages = .{ .capacity = 16, .refill_tokens = 16, .refill_period_ms = 1000 },
        .bytes = .{ .capacity = 1024, .refill_tokens = 1024, .refill_period_ms = 1000 },
        .commands = .{ .capacity = 16, .refill_tokens = 16, .refill_period_ms = 1000 },
        .target_changes = .{ .capacity = 2, .refill_tokens = 1, .refill_period_ms = 1000 },
        .excess = .{ .threshold = 10, .decay_points = 1, .decay_period_ms = 1000 },
        .max_tracked_targets = 4,
    });
    var guard = Guard.init(0);

    const first = try std.fmt.allocPrint(allocator, "PRIVMSG #a :one\r\n", .{});
    defer allocator.free(first);
    const repeat = try std.fmt.allocPrint(allocator, "privmsg #A :two\r\n", .{});
    defer allocator.free(repeat);
    const second = try std.fmt.allocPrint(allocator, "PRIVMSG #b :three\r\n", .{});
    defer allocator.free(second);
    const third = try std.fmt.allocPrint(allocator, "PRIVMSG #c :four\r\n", .{});
    defer allocator.free(third);

    try std.testing.expectEqual(Decision.allow, guard.classifyRaw(0, first));
    try std.testing.expectEqual(Decision.allow, guard.classifyRaw(0, repeat));
    try std.testing.expectEqual(Decision.allow, guard.classifyRaw(0, second));
    try std.testing.expectEqual(Decision.throttle, guard.classifyRaw(0, third));
    try std.testing.expectEqual(Decision.allow, guard.classifyRaw(1000, third));
}

test "deterministic with clock" {
    const allocator = std.testing.allocator;
    var a = TestGuard.init(50);
    var b = TestGuard.init(50);

    const lines = [_][]const u8{
        try std.fmt.allocPrint(allocator, "PING :a\r\n", .{}),
        try std.fmt.allocPrint(allocator, "PRIVMSG nick :b\r\n", .{}),
        try std.fmt.allocPrint(allocator, "PRIVMSG #chan :c\r\n", .{}),
        try std.fmt.allocPrint(allocator, "PING :d\r\n", .{}),
    };
    defer for (lines) |line| allocator.free(line);

    const times = [_]i64{ 50, 50, 40, 1050, 2050, 2050 };
    const indexes = [_]usize{ 0, 1, 2, 3, 0, 1 };

    var decisions_a: [times.len]Decision = undefined;
    var decisions_b: [times.len]Decision = undefined;
    for (times, indexes, 0..) |now_ms, idx, out_idx| {
        decisions_a[out_idx] = a.classifyRaw(now_ms, lines[idx]);
        decisions_b[out_idx] = b.classifyRaw(now_ms, lines[idx]);
    }

    try std.testing.expectEqualSlices(Decision, decisions_a[0..], decisions_b[0..]);
    try std.testing.expectEqual(a.snapshot(), b.snapshot());
}
