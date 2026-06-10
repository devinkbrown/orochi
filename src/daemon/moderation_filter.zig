//! Orochi moderation filter: rule-driven abuse handling with action ladders.
//!
//! The engine keeps operator-defined rules grouped by moderation surface and
//! uses the daemon's Koshi content matcher as the scan index for each surface.
//! Rule metadata and offender hit counters live here so a text match can map to
//! a steadily escalating moderation action.

const std = @import("std");
const content_filter = @import("content_filter.zig");

pub const Error = std.mem.Allocator.Error;

pub const FilterKind = enum {
    word,
    host_mask,
    flood,
    link,
};

pub const ActionType = enum(u8) {
    none = 0,
    warn = 1,
    mute = 2,
    kick = 3,
    ban = 4,
    global_ban = 5,
    kill = 6,
};

pub const Rule = struct {
    kind: FilterKind,
    pattern: []u8,
    action: ActionType,
    escalate_after: u8,
    expires_ms: i64,
};

const StoredRule = struct {
    id: u64,
    rule: Rule,
};

pub const Engine = struct {
    allocator: std.mem.Allocator,
    rules: std.ArrayListUnmanaged(StoredRule) = .empty,
    hits: std.StringHashMapUnmanaged(u8) = .empty,
    matchers: [kind_count]content_filter.ContentFilter,
    next_rule_id: u64 = 1,

    pub fn init(allocator: std.mem.Allocator) Engine {
        return .{
            .allocator = allocator,
            .matchers = .{
                content_filter.ContentFilter.init(allocator),
                content_filter.ContentFilter.init(allocator),
                content_filter.ContentFilter.init(allocator),
                content_filter.ContentFilter.init(allocator),
            },
        };
    }

    pub fn deinit(self: *Engine) void {
        for (self.rules.items) |stored| {
            self.allocator.free(stored.rule.pattern);
        }
        self.rules.deinit(self.allocator);

        var it = self.hits.keyIterator();
        while (it.next()) |key_ptr| {
            self.allocator.free(key_ptr.*);
        }
        self.hits.deinit(self.allocator);

        for (&self.matchers) |*matcher| {
            matcher.deinit();
        }
        self.* = undefined;
    }

    pub fn add(self: *Engine, rule: Rule) Error!bool {
        if (rule.pattern.len == 0) return false;
        if (self.indexOf(rule.kind, rule.pattern) != null) return false;

        const matcher = self.matcherFor(rule.kind);
        if (!try matcher.add(rule.pattern)) return false;
        errdefer _ = matcher.remove(rule.pattern) catch false;

        const owned_pattern = try self.allocator.dupe(u8, rule.pattern);
        errdefer self.allocator.free(owned_pattern);

        try self.rules.append(self.allocator, .{
            .id = self.next_rule_id,
            .rule = .{
                .kind = rule.kind,
                .pattern = owned_pattern,
                .action = rule.action,
                .escalate_after = rule.escalate_after,
                .expires_ms = rule.expires_ms,
            },
        });
        self.next_rule_id +%= 1;
        if (self.next_rule_id == 0) self.next_rule_id = 1;
        return true;
    }

    pub fn remove(self: *Engine, kind: FilterKind, pattern: []const u8) Error!bool {
        const idx = self.indexOf(kind, pattern) orelse return false;
        const stored = self.rules.items[idx];
        defer self.allocator.free(stored.rule.pattern);

        _ = try self.matcherFor(kind).remove(stored.rule.pattern);
        _ = self.rules.orderedRemove(idx);
        self.clearHitsFor(stored.id);
        return true;
    }

    pub fn evaluate(
        self: *Engine,
        kind: FilterKind,
        subject_text: []const u8,
        offender_key: []const u8,
        now_ms: i64,
    ) Error!ActionType {
        if (!self.matcherFor(kind).matches(subject_text)) return .none;

        var strongest: ActionType = .none;
        for (self.rules.items) |stored| {
            const rule = stored.rule;
            if (rule.kind != kind) continue;
            if (isExpired(rule.expires_ms, now_ms)) continue;
            if (!containsIgnoreCase(subject_text, rule.pattern)) continue;

            const hit_count = try self.bumpHit(stored.id, offender_key);
            strongest = maxAction(strongest, escalatedAction(rule.action, rule.escalate_after, hit_count));
        }
        return strongest;
    }

    fn matcherFor(self: *Engine, kind: FilterKind) *content_filter.ContentFilter {
        return &self.matchers[kindIndex(kind)];
    }

    fn indexOf(self: *const Engine, kind: FilterKind, pattern: []const u8) ?usize {
        for (self.rules.items, 0..) |stored, idx| {
            const rule = stored.rule;
            if (rule.kind == kind and std.ascii.eqlIgnoreCase(rule.pattern, pattern)) return idx;
        }
        return null;
    }

    fn bumpHit(self: *Engine, rule_id: u64, offender_key: []const u8) Error!u8 {
        const probe = try makeHitKey(self.allocator, rule_id, offender_key);
        errdefer self.allocator.free(probe);

        const gop = try self.hits.getOrPut(self.allocator, probe);
        if (gop.found_existing) {
            self.allocator.free(probe);
            gop.value_ptr.* = saturatingIncrement(gop.value_ptr.*);
        } else {
            gop.value_ptr.* = 1;
        }
        return gop.value_ptr.*;
    }

    fn clearHitsFor(self: *Engine, rule_id: u64) void {
        var doomed: std.ArrayListUnmanaged([]const u8) = .empty;
        defer doomed.deinit(self.allocator);

        var it = self.hits.keyIterator();
        while (it.next()) |key_ptr| {
            const key = key_ptr.*;
            if (keyHasRuleId(key, rule_id)) {
                doomed.append(self.allocator, key) catch break;
            }
        }

        for (doomed.items) |key| {
            if (self.hits.fetchRemove(key)) |removed| {
                self.allocator.free(removed.key);
            }
        }
    }
};

const kind_count = @typeInfo(FilterKind).@"enum".fields.len;
const hit_rule_bytes = @sizeOf(u64);

fn kindIndex(kind: FilterKind) usize {
    return switch (kind) {
        .word => 0,
        .host_mask => 1,
        .flood => 2,
        .link => 3,
    };
}

fn isExpired(expires_ms: i64, now_ms: i64) bool {
    return expires_ms > 0 and now_ms >= expires_ms;
}

fn maxAction(a: ActionType, b: ActionType) ActionType {
    return if (@intFromEnum(a) >= @intFromEnum(b)) a else b;
}

fn escalatedAction(base: ActionType, escalate_after: u8, hit_count: u8) ActionType {
    if (base == .none) return .none;
    if (escalate_after == 0) return bumpAction(base);
    if (hit_count <= escalate_after) return base;
    return bumpAction(base);
}

fn bumpAction(action: ActionType) ActionType {
    return switch (action) {
        .none => .warn,
        .warn => .mute,
        .mute => .kick,
        .kick => .ban,
        .ban => .global_ban,
        .global_ban => .kill,
        .kill => .kill,
    };
}

fn saturatingIncrement(value: u8) u8 {
    if (value == std.math.maxInt(u8)) return value;
    return value + 1;
}

fn containsIgnoreCase(text: []const u8, pattern: []const u8) bool {
    if (pattern.len == 0) return true;
    if (pattern.len > text.len) return false;

    var start: usize = 0;
    while (start + pattern.len <= text.len) : (start += 1) {
        var offset: usize = 0;
        while (offset < pattern.len) : (offset += 1) {
            const lhs = std.ascii.toLower(text[start + offset]);
            const rhs = std.ascii.toLower(pattern[offset]);
            if (lhs != rhs) break;
        } else {
            return true;
        }
    }
    return false;
}

fn makeHitKey(allocator: std.mem.Allocator, rule_id: u64, offender_key: []const u8) Error![]u8 {
    const key = try allocator.alloc(u8, hit_rule_bytes + offender_key.len);
    std.mem.writeInt(u64, key[0..hit_rule_bytes], rule_id, .little);
    @memcpy(key[hit_rule_bytes..], offender_key);
    return key;
}

fn keyHasRuleId(key: []const u8, rule_id: u64) bool {
    if (key.len < hit_rule_bytes) return false;
    return std.mem.readInt(u64, key[0..hit_rule_bytes], .little) == rule_id;
}

const testing = std.testing;

fn addTestRule(
    engine: *Engine,
    kind: FilterKind,
    pattern: []const u8,
    action: ActionType,
    escalate_after: u8,
    expires_ms: i64,
) !void {
    const owned = try testing.allocator.dupe(u8, pattern);
    defer testing.allocator.free(owned);
    try testing.expect(try engine.add(.{
        .kind = kind,
        .pattern = owned,
        .action = action,
        .escalate_after = escalate_after,
        .expires_ms = expires_ms,
    }));
}

test "word rule warns then escalates to mute after threshold hits" {
    var engine = Engine.init(testing.allocator);
    defer engine.deinit();

    try addTestRule(&engine, .word, "needle", .warn, 2, 0);

    try testing.expectEqual(ActionType.warn, try engine.evaluate(.word, "one NEEDLE", "acct:1", 10));
    try testing.expectEqual(ActionType.warn, try engine.evaluate(.word, "two needle", "acct:1", 20));
    try testing.expectEqual(ActionType.mute, try engine.evaluate(.word, "three needle", "acct:1", 30));
}

test "severity ordering keeps strongest matching rule" {
    var engine = Engine.init(testing.allocator);
    defer engine.deinit();

    try addTestRule(&engine, .link, "shared", .warn, 9, 0);
    try addTestRule(&engine, .link, "bad.example", .ban, 9, 0);

    const action = try engine.evaluate(.link, "https://bad.example/shared", "acct:2", 40);
    try testing.expectEqual(ActionType.ban, action);
}

test "expired rules do not act" {
    var engine = Engine.init(testing.allocator);
    defer engine.deinit();

    try addTestRule(&engine, .host_mask, "proxy", .kick, 1, 99);

    try testing.expectEqual(ActionType.kick, try engine.evaluate(.host_mask, "open-proxy", "addr:1", 98));
    try testing.expectEqual(ActionType.none, try engine.evaluate(.host_mask, "open-proxy", "addr:1", 99));
}

test "unknown text and removed rules return none" {
    var engine = Engine.init(testing.allocator);
    defer engine.deinit();

    try addTestRule(&engine, .flood, "burst", .mute, 3, 0);

    try testing.expectEqual(ActionType.none, try engine.evaluate(.flood, "quiet", "acct:3", 1));
    try testing.expect(try engine.remove(.flood, "BURST"));
    try testing.expectEqual(ActionType.none, try engine.evaluate(.flood, "burst", "acct:3", 2));
}
