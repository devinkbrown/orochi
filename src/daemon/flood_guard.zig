// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The single per-connection flood guard.
//!
//! This is the one flood rate-limiter in the daemon. Earlier the codebase carried
//! three overlapping mechanisms — a crude per-class line counter in the server, a
//! comptime token-bucket primitive (`flood.zig`), and a comptime guard composed
//! from it — none of which were operator-tunable at runtime. They are gone; this
//! module replaces all of them.
//!
//! Policy lives in the struct (not in comptime), so limits arrive from the per-
//! connection class (`conn_class.Policy.floodGuardConfig`) and retune live on
//! REHASH. The hot path is deterministic and allocation-free: callers pass
//! monotonic milliseconds; the guard never reads a clock. It keeps token-bucket +
//! leaky-excess math, lets any single dimension be disabled (capacity 0 =
//! unmetered), and adds **command-class weighting** — keep-alives (`PING`/`PONG`)
//! cost nothing, `PRIVMSG`/`NOTICE`/`JOIN` carry weight — plus a distinct-target
//! spread throttle that counters spray-spam without a repeated target.
//!
//! This guard is strictly per-connection (token-bucket state lives on the
//! connection and dies with it). A per-*account* abuse score that survived
//! reconnects would be a separate axis; this module does not model it.
const std = @import("std");

/// Result of a rate-control observation.
pub const Decision = enum { allow, throttle, disconnect };

/// One token-bucket dimension. `capacity == 0` disables the dimension entirely
/// (every consume succeeds), which is how an operator turns a check off.
pub const BucketCfg = struct {
    capacity: u64 = 0,
    refill_tokens: u64 = 0,
    refill_period_ms: u64 = 1000,
};

/// Leaky excess-flood policy. `threshold == 0` disables disconnect escalation:
/// offending lines are still reported as `.throttle`, the client is never cut.
pub const ExcessCfg = struct {
    threshold: u64 = 0,
    decay_points: u64 = 1,
    decay_period_ms: u64 = 1000,
};

/// Number of distinct recent PRIVMSG targets tracked per client for the
/// target-change (spread-spam) check. Fixed so the guard stays a flat value.
pub const target_slots: usize = 16;

/// Complete runtime flood policy. Built once from a connection class's policy and
/// shared by value into every guard via `reconfigure`, so a REHASH retunes live
/// clients.
pub const GuardConfig = struct {
    /// Master switch. When false the guard is inert and callers should skip it.
    enabled: bool = false,
    messages: BucketCfg = .{},
    bytes: BucketCfg = .{},
    commands: BucketCfg = .{},
    target_changes: BucketCfg = .{},
    excess: ExcessCfg = .{},
    /// Excess points added when a metered dimension (message/byte/command) trips.
    throttle_penalty: u64 = 1,
    /// Excess points added specifically when the distinct-target rate trips.
    target_change_penalty: u64 = 1,
    /// Weight charged to the command bucket for messaging commands.
    privmsg_weight: u64 = 1,
    /// Weight charged to the command bucket for JOIN (raid/cycle pressure).
    join_weight: u64 = 2,
    /// Weight charged to the command bucket for every other metered command.
    default_weight: u64 = 1,

    pub const Error = error{InvalidFloodConfig};

    /// Reject nonsensical policy at boot/REHASH rather than mis-metering live.
    pub fn validate(self: GuardConfig) Error!void {
        try validateBucket(self.messages);
        try validateBucket(self.bytes);
        try validateBucket(self.commands);
        try validateBucket(self.target_changes);
        if (self.excess.threshold != 0 and self.excess.decay_points != 0 and self.excess.decay_period_ms == 0) {
            return Error.InvalidFloodConfig;
        }
        if (self.throttle_penalty == 0 or self.target_change_penalty == 0) return Error.InvalidFloodConfig;
        if (self.default_weight == 0) return Error.InvalidFloodConfig;
    }

    fn validateBucket(b: BucketCfg) Error!void {
        if (b.capacity == 0) return; // disabled dimension
        if (b.refill_tokens != 0 and b.refill_period_ms == 0) return Error.InvalidFloodConfig;
    }
};

/// Parsed view of an IRC line: command verb, first parameter, and total byte cost.
pub const ParsedLine = struct {
    command: []const u8,
    first_param: []const u8 = "",
    byte_count: u64,
};

const RuntimeBucket = struct {
    cfg: BucketCfg,
    tokens: u64,
    last_ms: i64,
    carry: u64,

    fn init(cfg: BucketCfg, now_ms: i64) RuntimeBucket {
        return .{ .cfg = cfg, .tokens = cfg.capacity, .last_ms = now_ms, .carry = 0 };
    }

    fn available(self: *const RuntimeBucket) u64 {
        return self.tokens;
    }

    fn refill(self: *RuntimeBucket, now_ms: i64) void {
        if (self.cfg.capacity == 0) return;
        const elapsed_ms = elapsedMillis(self.last_ms, now_ms);
        if (elapsed_ms == 0) return;
        self.last_ms = now_ms;
        if (self.cfg.refill_tokens == 0 or self.cfg.refill_period_ms == 0) return;
        if (self.tokens >= self.cfg.capacity) {
            self.carry = 0;
            return;
        }
        const units = @as(u128, elapsed_ms) * @as(u128, self.cfg.refill_tokens) + @as(u128, self.carry);
        const add = units / @as(u128, self.cfg.refill_period_ms);
        if (add == 0) {
            self.carry = @intCast(units);
            return;
        }
        const room = self.cfg.capacity - self.tokens;
        if (add >= room) {
            self.tokens = self.cfg.capacity;
            self.carry = 0;
            return;
        }
        self.tokens += @intCast(add);
        self.carry = @intCast(units % @as(u128, self.cfg.refill_period_ms));
    }

    fn tryConsume(self: *RuntimeBucket, now_ms: i64, cost: u64) bool {
        if (self.cfg.capacity == 0) return true;
        self.refill(now_ms);
        if (cost == 0) return true;
        if (cost > self.tokens) return false;
        self.tokens -= cost;
        return true;
    }

    /// Adopt new policy live. Token balance is clamped into the new capacity so a
    /// REHASH that lowers a limit cannot leave a client holding stale credit.
    fn reconfigure(self: *RuntimeBucket, cfg: BucketCfg) void {
        self.cfg = cfg;
        if (cfg.capacity == 0) {
            self.tokens = 0;
            self.carry = 0;
        } else if (self.tokens > cfg.capacity) {
            self.tokens = cfg.capacity;
        }
    }
};

const RuntimeExcess = struct {
    cfg: ExcessCfg,
    points: u64,
    last_ms: i64,
    carry: u64,

    fn init(cfg: ExcessCfg, now_ms: i64) RuntimeExcess {
        return .{ .cfg = cfg, .points = 0, .last_ms = now_ms, .carry = 0 };
    }

    fn current(self: *const RuntimeExcess) u64 {
        return self.points;
    }

    fn decay(self: *RuntimeExcess, now_ms: i64) void {
        const elapsed_ms = elapsedMillis(self.last_ms, now_ms);
        if (elapsed_ms == 0) return;
        self.last_ms = now_ms;
        if (self.cfg.decay_points == 0 or self.cfg.decay_period_ms == 0 or self.points == 0) {
            self.carry = 0;
            return;
        }
        const units = @as(u128, elapsed_ms) * @as(u128, self.cfg.decay_points) + @as(u128, self.carry);
        const remove = units / @as(u128, self.cfg.decay_period_ms);
        if (remove == 0) {
            self.carry = @intCast(units);
            return;
        }
        if (remove >= self.points) {
            self.points = 0;
            self.carry = 0;
            return;
        }
        self.points -= @intCast(remove);
        self.carry = @intCast(units % @as(u128, self.cfg.decay_period_ms));
    }

    fn add(self: *RuntimeExcess, now_ms: i64, points: u64) Decision {
        self.decay(now_ms);
        self.points = saturatingAdd(self.points, points);
        if (self.cfg.threshold != 0 and self.points >= self.cfg.threshold) return .disconnect;
        return .throttle;
    }

    fn tripped(self: *const RuntimeExcess) bool {
        return self.cfg.threshold != 0 and self.points >= self.cfg.threshold;
    }

    fn reconfigure(self: *RuntimeExcess, cfg: ExcessCfg) void {
        self.cfg = cfg;
    }
};

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

/// Per-connection flood guard. Bounded, allocation-free, deterministic.
pub const FloodGuard = struct {
    config: GuardConfig,
    message_rate: RuntimeBucket,
    byte_rate: RuntimeBucket,
    command_rate: RuntimeBucket,
    target_change_rate: RuntimeBucket,
    excess: RuntimeExcess,
    targets: [target_slots]TargetKey = @splat(TargetKey.empty),
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

    pub fn init(config: GuardConfig, now_ms: i64) FloodGuard {
        return .{
            .config = config,
            .message_rate = RuntimeBucket.init(config.messages, now_ms),
            .byte_rate = RuntimeBucket.init(config.bytes, now_ms),
            .command_rate = RuntimeBucket.init(config.commands, now_ms),
            .target_change_rate = RuntimeBucket.init(config.target_changes, now_ms),
            .excess = RuntimeExcess.init(config.excess, now_ms),
        };
    }

    /// Retune a live guard to new policy (REHASH). Accumulated token/excess state
    /// is preserved and clamped, so a client mid-flood is neither pardoned nor
    /// double-charged by the config change.
    pub fn reconfigure(self: *FloodGuard, config: GuardConfig) void {
        self.config = config;
        self.message_rate.reconfigure(config.messages);
        self.byte_rate.reconfigure(config.bytes);
        self.command_rate.reconfigure(config.commands);
        self.target_change_rate.reconfigure(config.target_changes);
        self.excess.reconfigure(config.excess);
    }

    pub fn classifyRaw(self: *FloodGuard, now_ms: i64, raw_line: []const u8) Decision {
        return self.classifyParsed(now_ms, parseRaw(raw_line));
    }

    pub fn classifyParsed(self: *FloodGuard, now_ms: i64, line: ParsedLine) Decision {
        // Keep-alives never count against flood; the connection still has the
        // recv-buffer ceiling as a backstop against raw PING/PONG spam.
        const weight = self.commandWeight(line.command);
        if (weight == 0) {
            self.excess.decay(now_ms);
            if (self.excess.tripped()) return .disconnect;
            return .allow;
        }

        const message_ok = self.message_rate.tryConsume(now_ms, 1);
        const bytes_ok = self.byte_rate.tryConsume(now_ms, line.byte_count);
        const command_ok = self.command_rate.tryConsume(now_ms, weight);
        const target_ok = self.classifyTargetChange(now_ms, line);

        if (message_ok and bytes_ok and command_ok and target_ok) {
            self.excess.decay(now_ms);
            if (self.excess.tripped()) return .disconnect;
            return .allow;
        }

        const penalty = if (!target_ok) self.config.target_change_penalty else self.config.throttle_penalty;
        return self.excess.add(now_ms, penalty);
    }

    pub fn decay(self: *FloodGuard, now_ms: i64) void {
        self.message_rate.refill(now_ms);
        self.byte_rate.refill(now_ms);
        self.command_rate.refill(now_ms);
        self.target_change_rate.refill(now_ms);
        self.excess.decay(now_ms);
    }

    pub fn snapshot(self: *const FloodGuard) Snapshot {
        return .{
            .message_tokens = self.message_rate.available(),
            .byte_tokens = self.byte_rate.available(),
            .command_tokens = self.command_rate.available(),
            .target_change_tokens = self.target_change_rate.available(),
            .excess_points = self.excess.current(),
            .tracked_targets = self.target_count,
        };
    }

    fn commandWeight(self: *const FloodGuard, command: []const u8) u64 {
        if (eqIgnoreCase(command, "PING") or eqIgnoreCase(command, "PONG")) return 0;
        if (eqIgnoreCase(command, "PRIVMSG") or eqIgnoreCase(command, "NOTICE") or eqIgnoreCase(command, "TAGMSG")) {
            return self.config.privmsg_weight;
        }
        if (eqIgnoreCase(command, "JOIN")) return self.config.join_weight;
        return self.config.default_weight;
    }

    fn classifyTargetChange(self: *FloodGuard, now_ms: i64, line: ParsedLine) bool {
        if (!eqIgnoreCase(line.command, "PRIVMSG")) return true;
        if (line.first_param.len == 0) return true;

        const key = TargetKey.init(line.first_param);
        if (self.hasTarget(key)) return true;
        if (!self.target_change_rate.tryConsume(now_ms, 1)) return false;
        self.rememberTarget(key);
        return true;
    }

    fn hasTarget(self: *const FloodGuard, key: TargetKey) bool {
        for (self.targets[0..self.target_count]) |target| {
            if (target.eql(key)) return true;
        }
        return false;
    }

    fn rememberTarget(self: *FloodGuard, key: TargetKey) void {
        if (self.target_count < self.targets.len) {
            self.targets[self.target_count] = key;
            self.target_count += 1;
            return;
        }
        self.targets[self.next_target_slot] = key;
        self.next_target_slot = (self.next_target_slot + 1) % self.targets.len;
    }
};

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

fn eqIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

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

fn elapsedMillis(last_ms: i64, now_ms: i64) u64 {
    const delta = @as(i128, now_ms) - @as(i128, last_ms);
    if (delta <= 0) return 0;
    if (delta > std.math.maxInt(u64)) return std.math.maxInt(u64);
    return @intCast(delta);
}

fn saturatingAdd(a: u64, b: u64) u64 {
    const max = std.math.maxInt(u64);
    if (max - a < b) return max;
    return a + b;
}

const testing = std.testing;

fn testConfig() GuardConfig {
    return .{
        .enabled = true,
        .messages = .{},
        .bytes = .{},
        .commands = .{ .capacity = 2, .refill_tokens = 1, .refill_period_ms = 1000 },
        .target_changes = .{ .capacity = 8, .refill_tokens = 8, .refill_period_ms = 1000 },
        .excess = .{ .threshold = 10, .decay_points = 1, .decay_period_ms = 1000 },
    };
}

test "a valid config passes validation" {
    try testConfig().validate();
}

test "burst then throttle then recover" {
    var guard = FloodGuard.init(testConfig(), 0);
    const line = "WHOIS orochi\r\n";
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, line));
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, line));
    try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, line));
    try testing.expectEqual(Decision.allow, guard.classifyRaw(1000, line));
}

test "keep-alives are never metered" {
    var guard = FloodGuard.init(testConfig(), 0);
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "PING :x\r\n"));
    }
}

test "command weighting makes PRIVMSG cost more" {
    var cfg = testConfig();
    cfg.commands = .{ .capacity = 4, .refill_tokens = 1, .refill_period_ms = 1000 };
    cfg.privmsg_weight = 2;
    var guard = FloodGuard.init(cfg, 0);
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "PRIVMSG #a :hi\r\n"));
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "PRIVMSG #a :hi\r\n"));
    try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, "PRIVMSG #a :hi\r\n"));
}

test "distinct-target spread throttles" {
    var cfg = testConfig();
    cfg.commands = .{ .capacity = 100, .refill_tokens = 100, .refill_period_ms = 1000 };
    cfg.target_changes = .{ .capacity = 2, .refill_tokens = 1, .refill_period_ms = 1000 };
    var guard = FloodGuard.init(cfg, 0);
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "PRIVMSG #a :one\r\n"));
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "privmsg #A :two\r\n")); // same target, case-folded
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "PRIVMSG #b :three\r\n"));
    try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, "PRIVMSG #c :four\r\n"));
}

test "disabled dimension never blocks" {
    var cfg = testConfig();
    cfg.commands = .{};
    cfg.target_changes = .{};
    var guard = FloodGuard.init(cfg, 0);
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "PRIVMSG #a :spam\r\n"));
    }
}

test "threshold zero throttles forever but never disconnects" {
    var cfg = testConfig();
    cfg.excess = .{ .threshold = 0, .decay_points = 1, .decay_period_ms = 1000 };
    var guard = FloodGuard.init(cfg, 0);
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "WHOIS a\r\n"));
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "WHOIS a\r\n"));
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, "WHOIS a\r\n"));
    }
}

test "excess accumulation eventually disconnects" {
    var cfg = testConfig();
    cfg.excess = .{ .threshold = 3, .decay_points = 1, .decay_period_ms = 100000 };
    var guard = FloodGuard.init(cfg, 0);
    _ = guard.classifyRaw(0, "WHOIS a\r\n"); // allow
    _ = guard.classifyRaw(0, "WHOIS a\r\n"); // allow (bucket now empty)
    try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, "WHOIS a\r\n")); // +1
    try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, "WHOIS a\r\n")); // +1
    try testing.expectEqual(Decision.disconnect, guard.classifyRaw(0, "WHOIS a\r\n")); // +1 => 3
}

test "reconfigure clamps tokens and retunes live" {
    var guard = FloodGuard.init(testConfig(), 0);
    _ = guard.classifyRaw(0, "WHOIS a\r\n");
    var tighter = testConfig();
    tighter.commands = .{ .capacity = 1, .refill_tokens = 1, .refill_period_ms = 1000 };
    guard.reconfigure(tighter);
    try testing.expect(guard.snapshot().command_tokens <= 1);
}

test "deterministic for identical inputs" {
    var a = FloodGuard.init(testConfig(), 50);
    var b = FloodGuard.init(testConfig(), 50);
    const lines = [_][]const u8{ "PING :a\r\n", "PRIVMSG nick :b\r\n", "PRIVMSG #chan :c\r\n", "WHOIS d\r\n" };
    const times = [_]i64{ 50, 50, 40, 1050, 2050, 2050 };
    const idxs = [_]usize{ 0, 1, 2, 3, 0, 1 };
    for (times, idxs) |now_ms, idx| {
        try testing.expectEqual(a.classifyRaw(now_ms, lines[idx]), b.classifyRaw(now_ms, lines[idx]));
    }
    try testing.expectEqual(a.snapshot(), b.snapshot());
}

test "invalid config rejected" {
    var bad = testConfig();
    bad.throttle_penalty = 0;
    try testing.expectError(GuardConfig.Error.InvalidFloodConfig, bad.validate());
}
