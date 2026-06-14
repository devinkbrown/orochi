//! Suimyaku mesh user-message relay codec and loop guard.
//!
//! Relayed PRIVMSG/NOTICE/TAGMSG payloads are canonical CoilPack maps. The
//! schema is intentionally small and strict so the exact encoded bytes remain
//! stable for signing and forwarding decisions.

const std = @import("std");

const cpv = @import("../../proto/coilpack_value.zig");

pub const Verb = enum(u8) {
    privmsg = 1,
    notice = 2,
    tagmsg = 3,
};

pub const RelayMessage = struct {
    verb: Verb,
    target: []const u8,
    /// STATUSMSG delivery floor for channel targets (0 = every member, 1 = +,
    /// 2 = @, 3 = owner, 4 = founder). The target stays the bare channel name.
    min_rank: u8 = 0,
    source_nick: []const u8,
    source_prefix: []const u8,
    account: []const u8 = "",
    tags: []const u8 = "",
    text: []const u8,
    origin_node: u64,
    hlc: u64,
};

pub const Owned = struct {
    msg: RelayMessage,

    pub fn deinit(self: *Owned, allocator: std.mem.Allocator) void {
        allocator.free(self.msg.target);
        allocator.free(self.msg.source_nick);
        allocator.free(self.msg.source_prefix);
        allocator.free(self.msg.account);
        allocator.free(self.msg.tags);
        allocator.free(self.msg.text);
        self.* = undefined;
    }
};

pub const DecodeError = error{
    InvalidDocument,
    InvalidFieldType,
    InvalidVerb,
    MissingField,
    UnknownField,
};

/// Canonical CoilPack encode (stable field order - signature-stable).
pub fn encode(allocator: std.mem.Allocator, msg: RelayMessage) ![]u8 {
    var entries = [_]cpv.MapEntry{
        .{ .key = "account", .value = .{ .string = msg.account } },
        .{ .key = "hlc", .value = .{ .unsigned = msg.hlc } },
        .{ .key = "min_rank", .value = .{ .unsigned = msg.min_rank } },
        .{ .key = "origin_node", .value = .{ .unsigned = msg.origin_node } },
        .{ .key = "source_nick", .value = .{ .string = msg.source_nick } },
        .{ .key = "source_prefix", .value = .{ .string = msg.source_prefix } },
        .{ .key = "tags", .value = .{ .string = msg.tags } },
        .{ .key = "target", .value = .{ .string = msg.target } },
        .{ .key = "text", .value = .{ .string = msg.text } },
        .{ .key = "verb", .value = .{ .unsigned = @intFromEnum(msg.verb) } },
    };
    return cpv.Encoder.encode(allocator, .{ .map = entries[0..] });
}

/// Decode into owned copies (validates field presence + verb range).
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !Owned {
    var value = try cpv.Decoder.decode(allocator, bytes);
    defer value.deinit(allocator);

    const entries = switch (value) {
        .map => |entries| entries,
        else => return DecodeError.InvalidDocument,
    };

    var verb_opt: ?Verb = null;
    var target_opt: ?[]const u8 = null;
    var source_nick_opt: ?[]const u8 = null;
    var source_prefix_opt: ?[]const u8 = null;
    var account_opt: ?[]const u8 = null;
    var tags_opt: ?[]const u8 = null;
    var text_opt: ?[]const u8 = null;
    var min_rank: u8 = 0;
    var origin_node_opt: ?u64 = null;
    var hlc_opt: ?u64 = null;

    for (entries) |entry| {
        if (std.mem.eql(u8, entry.key, "account")) {
            account_opt = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "hlc")) {
            hlc_opt = try readU64(entry.value);
        } else if (std.mem.eql(u8, entry.key, "min_rank")) {
            min_rank = try readRank(entry.value);
        } else if (std.mem.eql(u8, entry.key, "origin_node")) {
            origin_node_opt = try readU64(entry.value);
        } else if (std.mem.eql(u8, entry.key, "source_nick")) {
            source_nick_opt = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "source_prefix")) {
            source_prefix_opt = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "tags")) {
            tags_opt = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "target")) {
            target_opt = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "text")) {
            text_opt = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "verb")) {
            verb_opt = try readVerb(entry.value);
        } else {
            return DecodeError.UnknownField;
        }
    }

    const target = target_opt orelse return DecodeError.MissingField;
    const source_nick = source_nick_opt orelse return DecodeError.MissingField;
    const source_prefix = source_prefix_opt orelse return DecodeError.MissingField;
    const account = account_opt orelse return DecodeError.MissingField;
    const tags = tags_opt orelse return DecodeError.MissingField;
    const text = text_opt orelse return DecodeError.MissingField;

    const target_owned = try allocator.dupe(u8, target);
    errdefer allocator.free(target_owned);
    const source_nick_owned = try allocator.dupe(u8, source_nick);
    errdefer allocator.free(source_nick_owned);
    const source_prefix_owned = try allocator.dupe(u8, source_prefix);
    errdefer allocator.free(source_prefix_owned);
    const account_owned = try allocator.dupe(u8, account);
    errdefer allocator.free(account_owned);
    const tags_owned = try allocator.dupe(u8, tags);
    errdefer allocator.free(tags_owned);
    const text_owned = try allocator.dupe(u8, text);
    errdefer allocator.free(text_owned);

    return .{ .msg = .{
        .verb = verb_opt orelse return DecodeError.MissingField,
        .target = target_owned,
        .source_nick = source_nick_owned,
        .source_prefix = source_prefix_owned,
        .account = account_owned,
        .tags = tags_owned,
        .text = text_owned,
        .min_rank = min_rank,
        .origin_node = origin_node_opt orelse return DecodeError.MissingField,
        .hlc = hlc_opt orelse return DecodeError.MissingField,
    } };
}

pub const SeenSet = struct {
    const Key = struct {
        origin_node: u64,
        hlc: u64,
    };

    allocator: std.mem.Allocator,
    capacity: usize,
    seen: std.AutoHashMapUnmanaged(Key, void) = .empty,
    order: std.ArrayListUnmanaged(Key) = .empty,
    next_evict: usize = 0,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) SeenSet {
        return .{ .allocator = allocator, .capacity = capacity };
    }

    pub fn observe(self: *SeenSet, origin_node: u64, hlc: u64) bool {
        if (self.capacity == 0) return false;

        const key = Key{ .origin_node = origin_node, .hlc = hlc };
        if (self.seen.contains(key)) return true;
        self.ensureCapacity() catch return true;

        if (self.order.items.len < self.capacity) {
            self.order.append(self.allocator, key) catch return true;
            self.seen.put(self.allocator, key, {}) catch return true;
            return false;
        }

        const evicted = self.order.items[self.next_evict];
        _ = self.seen.remove(evicted);
        self.order.items[self.next_evict] = key;
        self.next_evict = (self.next_evict + 1) % self.capacity;
        self.seen.put(self.allocator, key, {}) catch return true;
        return false;
    }

    pub fn deinit(self: *SeenSet) void {
        self.seen.deinit(self.allocator);
        self.order.deinit(self.allocator);
        self.* = undefined;
    }

    fn ensureCapacity(self: *SeenSet) !void {
        try self.seen.ensureTotalCapacity(self.allocator, @intCast(self.capacity));
        try self.order.ensureTotalCapacity(self.allocator, self.capacity);
    }
};

fn readString(value: cpv.Value) DecodeError![]const u8 {
    return switch (value) {
        .string => |string| string,
        else => DecodeError.InvalidFieldType,
    };
}

fn readU64(value: cpv.Value) DecodeError!u64 {
    return switch (value) {
        .unsigned => |n| n,
        else => DecodeError.InvalidFieldType,
    };
}

fn readVerb(value: cpv.Value) DecodeError!Verb {
    const raw = try readU64(value);
    return switch (raw) {
        1 => .privmsg,
        2 => .notice,
        3 => .tagmsg,
        else => DecodeError.InvalidVerb,
    };
}

fn readRank(value: cpv.Value) DecodeError!u8 {
    const raw = try readU64(value);
    if (raw > 4) return DecodeError.InvalidFieldType;
    return @intCast(raw);
}

fn expectRoundTrip(msg: RelayMessage) !void {
    const allocator = std.testing.allocator;
    const wire = try encode(allocator, msg);
    defer allocator.free(wire);

    var owned = try decode(allocator, wire);
    defer owned.deinit(allocator);

    try std.testing.expectEqual(msg.verb, owned.msg.verb);
    try std.testing.expectEqualStrings(msg.target, owned.msg.target);
    try std.testing.expectEqualStrings(msg.source_nick, owned.msg.source_nick);
    try std.testing.expectEqualStrings(msg.source_prefix, owned.msg.source_prefix);
    try std.testing.expectEqualStrings(msg.account, owned.msg.account);
    try std.testing.expectEqualStrings(msg.tags, owned.msg.tags);
    try std.testing.expectEqualStrings(msg.text, owned.msg.text);
    try std.testing.expectEqual(msg.min_rank, owned.msg.min_rank);
    try std.testing.expectEqual(msg.origin_node, owned.msg.origin_node);
    try std.testing.expectEqual(msg.hlc, owned.msg.hlc);
}

test "relay messages round-trip for each verb" {
    try expectRoundTrip(.{
        .verb = .privmsg,
        .target = "#orochi",
        .source_nick = "alice",
        .source_prefix = "alice!u@example.invalid",
        .account = "alice",
        .tags = "+draft/reply=42",
        .text = "hello mesh",
        .min_rank = 2,
        .origin_node = 7,
        .hlc = 101,
    });

    try expectRoundTrip(.{
        .verb = .notice,
        .target = "bob",
        .source_nick = "service",
        .source_prefix = "service!svc@example.invalid",
        .account = "",
        .tags = "",
        .text = "maintenance soon",
        .origin_node = 8,
        .hlc = 102,
    });

    try expectRoundTrip(.{
        .verb = .tagmsg,
        .target = "#orochi",
        .source_nick = "carol",
        .source_prefix = "carol!u@example.invalid",
        .account = "",
        .tags = "+typing=active",
        .text = "",
        .origin_node = 9,
        .hlc = 103,
    });
}

test "decode rejects truncated and garbage buffers" {
    const allocator = std.testing.allocator;
    const wire = try encode(allocator, .{
        .verb = .privmsg,
        .target = "#x",
        .source_nick = "n",
        .source_prefix = "n!u@h",
        .text = "hi",
        .origin_node = 1,
        .hlc = 2,
    });
    defer allocator.free(wire);

    try std.testing.expectError(cpv.FormatError.Truncated, decode(allocator, wire[0 .. wire.len - 1]));
    try std.testing.expectError(cpv.FormatError.UnknownTag, decode(allocator, &.{0xff}));
}

test "seen set detects repeats and evicts oldest" {
    var seen = SeenSet.init(std.testing.allocator, 2);
    defer seen.deinit();

    try std.testing.expect(!seen.observe(1, 10));
    try std.testing.expect(seen.observe(1, 10));
    try std.testing.expect(!seen.observe(2, 20));
    try std.testing.expect(!seen.observe(3, 30));
    try std.testing.expect(!seen.observe(1, 10));
    try std.testing.expect(seen.observe(3, 30));
}
