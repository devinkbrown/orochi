//! Pure channel-history policy data and parser.
//!
//! This module intentionally contains no service pseudo-client behavior. It
//! parses real IRC command lines (`CHANHISTPOLICY` and `CHATHISTORY POLICY`) and
//! exposes standard IRC numeric mappings for failures, leaving all I/O and
//! reply formatting to the daemon.

const std = @import("std");

pub const command_name = "CHANHISTPOLICY";
pub const chathistory_command_name = "CHATHISTORY";
pub const chathistory_policy_subcommand = "POLICY";

pub const max_channel_bytes: usize = 128;
pub const max_tokens: usize = 16;

pub const Numeric = enum(u16) {
    ERR_NOSUCHCHANNEL = 403,
    ERR_UNKNOWNCOMMAND = 421,
    ERR_NEEDMOREPARAMS = 461,
    ERR_CHANOPRIVSNEEDED = 482,
};

pub const Field = enum {
    ops,
    playback_on_join,
};

pub const Policy = struct {
    /// When true, channel-history use is limited to channel operators.
    ops: bool = false,
    /// When true, eligible clients may receive history automatically on JOIN.
    playback_on_join: bool = false,

    pub fn init(ops: bool, playback_on_join: bool) Policy {
        return .{ .ops = ops, .playback_on_join = playback_on_join };
    }

    pub fn get(self: Policy, field: Field) bool {
        return switch (field) {
            .ops => self.ops,
            .playback_on_join => self.playback_on_join,
        };
    }

    pub fn set(self: *Policy, field: Field, value: bool) void {
        switch (field) {
            .ops => self.ops = value,
            .playback_on_join => self.playback_on_join = value,
        }
    }

    pub fn with(self: Policy, field: Field, value: bool) Policy {
        var next = self;
        next.set(field, value);
        return next;
    }

    pub fn apply(self: *Policy, changes: ChangeSet) void {
        if (changes.ops) |value| self.ops = value;
        if (changes.playback_on_join) |value| self.playback_on_join = value;
    }

    pub fn eql(self: Policy, other: Policy) bool {
        return self.ops == other.ops and self.playback_on_join == other.playback_on_join;
    }

    pub fn canUseHistory(self: Policy, actor_is_channel_operator: bool) bool {
        return !self.ops or actor_is_channel_operator;
    }

    pub fn shouldPlaybackOnJoin(self: Policy, actor_is_channel_operator: bool) bool {
        return self.playback_on_join and self.canUseHistory(actor_is_channel_operator);
    }
};

pub const ChangeSet = struct {
    ops: ?bool = null,
    playback_on_join: ?bool = null,

    pub fn set(self: *ChangeSet, field: Field, value: bool) ParseError!void {
        switch (field) {
            .ops => {
                if (self.ops != null) return error.DuplicateField;
                self.ops = value;
            },
            .playback_on_join => {
                if (self.playback_on_join != null) return error.DuplicateField;
                self.playback_on_join = value;
            },
        }
    }

    pub fn get(self: ChangeSet, field: Field) ?bool {
        return switch (field) {
            .ops => self.ops,
            .playback_on_join => self.playback_on_join,
        };
    }

    pub fn isEmpty(self: ChangeSet) bool {
        return self.ops == null and self.playback_on_join == null;
    }

    pub fn applyTo(self: ChangeSet, policy: Policy) Policy {
        var next = policy;
        next.apply(self);
        return next;
    }
};

pub const Query = struct {
    channel: []const u8,
    field: ?Field = null,
};

pub const Update = struct {
    channel: []const u8,
    changes: ChangeSet,
};

pub const Request = union(enum) {
    get: Query,
    set: Update,
};

pub const ParseOptions = struct {
    max_channel_len: usize = max_channel_bytes,
};

pub const ParseError = error{
    NeedMoreParams,
    TooManyParams,
    UnknownCommand,
    InvalidParams,
    InvalidChannel,
    InvalidField,
    InvalidValue,
    DuplicateField,
    EmptyUpdate,
};

pub fn numericForParseError(err: ParseError) Numeric {
    return switch (err) {
        error.UnknownCommand => .ERR_UNKNOWNCOMMAND,
        error.InvalidChannel => .ERR_NOSUCHCHANNEL,
        error.NeedMoreParams => .ERR_NEEDMOREPARAMS,
        error.TooManyParams,
        error.InvalidParams,
        error.InvalidField,
        error.InvalidValue,
        error.DuplicateField,
        error.EmptyUpdate,
        => .ERR_NEEDMOREPARAMS,
    };
}

pub const AccessError = error{
    ChanopPrivsNeeded,
};

pub fn numericForAccessError(err: AccessError) Numeric {
    return switch (err) {
        error.ChanopPrivsNeeded => .ERR_CHANOPRIVSNEEDED,
    };
}

pub fn requireHistoryAccess(policy: Policy, actor_is_channel_operator: bool) AccessError!void {
    if (!policy.canUseHistory(actor_is_channel_operator)) return error.ChanopPrivsNeeded;
}

pub const Registry = struct {
    allocator: std.mem.Allocator,
    default_policy: Policy = .{},
    channels: std.StringHashMap(Policy),

    pub fn init(allocator: std.mem.Allocator) Registry {
        return initWithDefault(allocator, .{});
    }

    pub fn initWithDefault(allocator: std.mem.Allocator, default_policy: Policy) Registry {
        return .{
            .allocator = allocator,
            .default_policy = default_policy,
            .channels = std.StringHashMap(Policy).init(allocator),
        };
    }

    pub fn deinit(self: *Registry) void {
        var it = self.channels.keyIterator();
        while (it.next()) |key| self.allocator.free(key.*);
        self.channels.deinit();
        self.* = undefined;
    }

    pub fn get(self: *const Registry, channel: []const u8) Policy {
        return self.channels.get(channel) orelse self.default_policy;
    }

    pub fn getField(self: *const Registry, channel: []const u8, field: Field) bool {
        return self.get(channel).get(field);
    }

    pub fn set(self: *Registry, channel: []const u8, field: Field, value: bool) !Policy {
        var policy = self.get(channel);
        policy.set(field, value);
        try self.put(channel, policy);
        return policy;
    }

    pub fn apply(self: *Registry, update: Update) !Policy {
        var policy = self.get(update.channel);
        policy.apply(update.changes);
        try self.put(update.channel, policy);
        return policy;
    }

    pub fn put(self: *Registry, channel: []const u8, policy: Policy) !void {
        try validateChannel(channel, self.maxChannelLen());
        const gop = try self.channels.getOrPut(channel);
        if (!gop.found_existing) {
            errdefer _ = self.channels.remove(channel);
            const owned = try self.allocator.dupe(u8, channel);
            gop.key_ptr.* = owned;
        }
        gop.value_ptr.* = policy;
    }

    pub fn clear(self: *Registry, channel: []const u8) bool {
        if (self.channels.fetchRemove(channel)) |entry| {
            self.allocator.free(entry.key);
            return true;
        }
        return false;
    }

    pub fn count(self: *const Registry) usize {
        return self.channels.count();
    }

    fn maxChannelLen(_: *const Registry) usize {
        return max_channel_bytes;
    }
};

pub fn parse(line: []const u8) ParseError!Request {
    return parseWithOptions(line, .{});
}

pub fn parseWithOptions(line: []const u8, options: ParseOptions) ParseError!Request {
    const trimmed = std.mem.trim(u8, line, "\r\n");
    var tokens: [max_tokens][]const u8 = undefined;
    const count = try tokenize(trimmed, &tokens);
    if (count == 0) return error.NeedMoreParams;

    const offset = try commandPayloadOffset(tokens[0..count]);
    if (count <= offset) return error.NeedMoreParams;

    const channel = tokens[offset];
    try validateChannel(channel, options.max_channel_len);

    const rest = tokens[offset + 1 .. count];
    if (rest.len == 0) return .{ .get = .{ .channel = channel } };

    if (std.ascii.eqlIgnoreCase(rest[0], "GET")) {
        if (rest.len == 1) return .{ .get = .{ .channel = channel } };
        if (rest.len == 2) return .{ .get = .{ .channel = channel, .field = try parseField(rest[1]) } };
        return error.TooManyParams;
    }

    if (std.ascii.eqlIgnoreCase(rest[0], "SET")) {
        if (rest.len == 1) return error.EmptyUpdate;
        const changes = try parseSetPairs(rest[1..]);
        return .{ .set = .{ .channel = channel, .changes = changes } };
    }

    if (rest.len == 1) {
        if (parseField(rest[0])) |field| {
            return .{ .get = .{ .channel = channel, .field = field } };
        } else |_| {}
    }

    const changes = try parseToggleList(rest);
    return .{ .set = .{ .channel = channel, .changes = changes } };
}

pub fn parseField(token: []const u8) ParseError!Field {
    if (fieldNameEql(token, "ops")) return .ops;
    if (fieldNameEql(token, "playback_on_join")) return .playback_on_join;
    if (fieldNameEql(token, "playback-on-join")) return .playback_on_join;
    if (fieldNameEql(token, "playbackonjoin")) return .playback_on_join;
    return error.InvalidField;
}

pub fn parseBool(token: []const u8) ParseError!bool {
    if (std.ascii.eqlIgnoreCase(token, "on")) return true;
    if (std.ascii.eqlIgnoreCase(token, "true")) return true;
    if (std.ascii.eqlIgnoreCase(token, "yes")) return true;
    if (std.mem.eql(u8, token, "1")) return true;

    if (std.ascii.eqlIgnoreCase(token, "off")) return false;
    if (std.ascii.eqlIgnoreCase(token, "false")) return false;
    if (std.ascii.eqlIgnoreCase(token, "no")) return false;
    if (std.mem.eql(u8, token, "0")) return false;

    return error.InvalidValue;
}

pub fn validateChannel(channel: []const u8, max_len: usize) ParseError!void {
    if (channel.len < 2 or channel.len > max_len) return error.InvalidChannel;
    if (channel[0] != '#' and channel[0] != '&') return error.InvalidChannel;

    for (channel[1..]) |byte| {
        switch (byte) {
            0, 7, 10, 13, ' ', ',', ':' => return error.InvalidChannel,
            else => {},
        }
    }
}

fn tokenize(line: []const u8, out: *[max_tokens][]const u8) ParseError!usize {
    var count: usize = 0;
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    while (it.next()) |token| {
        if (count == out.len) return error.TooManyParams;
        out[count] = token;
        count += 1;
    }
    return count;
}

fn commandPayloadOffset(tokens: []const []const u8) ParseError!usize {
    if (std.ascii.eqlIgnoreCase(tokens[0], command_name)) return 1;
    if (std.ascii.eqlIgnoreCase(tokens[0], chathistory_command_name)) {
        if (tokens.len < 2) return error.NeedMoreParams;
        if (!std.ascii.eqlIgnoreCase(tokens[1], chathistory_policy_subcommand)) return error.UnknownCommand;
        return 2;
    }
    return error.UnknownCommand;
}

fn parseSetPairs(tokens: []const []const u8) ParseError!ChangeSet {
    if (tokens.len == 0) return error.EmptyUpdate;
    if (tokens.len % 2 != 0) return error.InvalidParams;

    var changes: ChangeSet = .{};
    var index: usize = 0;
    while (index < tokens.len) : (index += 2) {
        try changes.set(try parseField(tokens[index]), try parseBool(tokens[index + 1]));
    }
    return changes;
}

fn parseToggleList(tokens: []const []const u8) ParseError!ChangeSet {
    var changes: ChangeSet = .{};
    for (tokens) |token| {
        if (token.len < 2) return error.InvalidParams;

        if (token[0] == '+' or token[0] == '-') {
            try changes.set(try parseField(token[1..]), token[0] == '+');
            continue;
        }

        if (std.mem.indexOfScalar(u8, token, '=')) |equals| {
            if (equals == 0 or equals + 1 == token.len) return error.InvalidParams;
            try changes.set(try parseField(token[0..equals]), try parseBool(token[equals + 1 ..]));
            continue;
        }

        return error.InvalidParams;
    }

    if (changes.isEmpty()) return error.EmptyUpdate;
    return changes;
}

fn fieldNameEql(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

const testing = std.testing;

test "policy set get apply and join playback logic" {
    var policy = Policy{};
    try testing.expect(!policy.get(.ops));
    try testing.expect(!policy.get(.playback_on_join));
    try testing.expect(policy.canUseHistory(false));
    try testing.expect(!policy.shouldPlaybackOnJoin(true));

    policy.set(.playback_on_join, true);
    try testing.expect(policy.shouldPlaybackOnJoin(false));

    policy.set(.ops, true);
    try testing.expect(!policy.canUseHistory(false));
    try testing.expect(policy.canUseHistory(true));
    try testing.expect(!policy.shouldPlaybackOnJoin(false));
    try testing.expect(policy.shouldPlaybackOnJoin(true));

    const changed = policy.with(.ops, false);
    try testing.expect(!changed.ops);
    try testing.expect(changed.playback_on_join);
}

test "changeset tracks optional fields and rejects duplicates" {
    var changes: ChangeSet = .{};
    try testing.expect(changes.isEmpty());

    try changes.set(.ops, true);
    try testing.expectEqual(true, changes.get(.ops).?);
    try testing.expect(changes.get(.playback_on_join) == null);
    try testing.expectError(error.DuplicateField, changes.set(.ops, false));

    try changes.set(.playback_on_join, true);
    const applied = changes.applyTo(.{});
    try testing.expect(applied.ops);
    try testing.expect(applied.playback_on_join);
}

test "registry set get default and clear" {
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();

    try testing.expectEqual(Policy{}, registry.get("#ops"));
    try testing.expectEqual(@as(usize, 0), registry.count());

    const after_ops = try registry.set("#ops", .ops, true);
    try testing.expect(after_ops.ops);
    try testing.expect(registry.getField("#ops", .ops));
    try testing.expect(!registry.getField("#ops", .playback_on_join));
    try testing.expectEqual(@as(usize, 1), registry.count());

    const after_playback = try registry.apply(.{
        .channel = "#ops",
        .changes = .{ .playback_on_join = true },
    });
    try testing.expect(after_playback.ops);
    try testing.expect(after_playback.playback_on_join);
    try testing.expectEqual(@as(usize, 1), registry.count());

    try testing.expect(registry.clear("#ops"));
    try testing.expect(!registry.clear("#ops"));
    try testing.expectEqual(Policy{}, registry.get("#ops"));
}

test "registry owns channel keys independent of caller buffer" {
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();

    var channel_buf = [_]u8{ '#', 't', 'm', 'p' };
    try registry.put(channel_buf[0..], .{ .ops = true });
    @memcpy(channel_buf[0..], "#bad");

    try testing.expect(registry.get("#tmp").ops);
    try testing.expect(!registry.get("#bad").ops);
}

test "registry accepts custom default policy without allocation on read" {
    var registry = Registry.initWithDefault(testing.allocator, .{ .playback_on_join = true });
    defer registry.deinit();

    try testing.expect(registry.get("#new").playback_on_join);
    try testing.expectEqual(@as(usize, 0), registry.count());
}

test "parse chanhistpolicy get whole policy" {
    const request = try parse("CHANHISTPOLICY #zig\r\n");
    switch (request) {
        .get => |query| {
            try testing.expectEqualStrings("#zig", query.channel);
            try testing.expect(query.field == null);
        },
        else => return error.TestExpectedEqual,
    }
}

test "parse chathistory policy get field" {
    const request = try parse("CHATHISTORY POLICY #zig GET playback-on-join");
    switch (request) {
        .get => |query| {
            try testing.expectEqualStrings("#zig", query.channel);
            try testing.expectEqual(Field.playback_on_join, query.field.?);
        },
        else => return error.TestExpectedEqual,
    }
}

test "parse bare field as field query" {
    const request = try parse("chanhistpolicy #zig OPS");
    switch (request) {
        .get => |query| try testing.expectEqual(Field.ops, query.field.?),
        else => return error.TestExpectedEqual,
    }
}

test "parse set pairs" {
    const request = try parse("CHANHISTPOLICY #zig SET ops on playback_on_join off");
    switch (request) {
        .set => |update| {
            try testing.expectEqualStrings("#zig", update.channel);
            try testing.expectEqual(true, update.changes.ops.?);
            try testing.expectEqual(false, update.changes.playback_on_join.?);
        },
        else => return error.TestExpectedEqual,
    }
}

test "parse toggle list with plus minus syntax" {
    const request = try parse("CHANHISTPOLICY #zig +ops -playback_on_join");
    switch (request) {
        .set => |update| {
            try testing.expectEqual(true, update.changes.ops.?);
            try testing.expectEqual(false, update.changes.playback_on_join.?);
        },
        else => return error.TestExpectedEqual,
    }
}

test "parse toggle list with equals syntax" {
    const request = try parse("CHATHISTORY POLICY #zig ops=false playbackonjoin=yes");
    switch (request) {
        .set => |update| {
            try testing.expectEqual(false, update.changes.ops.?);
            try testing.expectEqual(true, update.changes.playback_on_join.?);
        },
        else => return error.TestExpectedEqual,
    }
}

test "parse bool aliases" {
    try testing.expect(try parseBool("on"));
    try testing.expect(try parseBool("TRUE"));
    try testing.expect(try parseBool("yes"));
    try testing.expect(try parseBool("1"));
    try testing.expect(!(try parseBool("off")));
    try testing.expect(!(try parseBool("FALSE")));
    try testing.expect(!(try parseBool("no")));
    try testing.expect(!(try parseBool("0")));
    try testing.expectError(error.InvalidValue, parseBool("maybe"));
}

test "parse rejects pseudo-client service commands" {
    try testing.expectError(error.UnknownCommand, parse("PRIVMSG ChanServ :SET #zig CHANHIST +ops"));
    try testing.expectError(error.UnknownCommand, parse("PRIVMSG NickServ :INFO #zig"));
    try testing.expectError(error.UnknownCommand, parse("NOTICE OperServ :CHANHISTPOLICY #zig +ops"));
}

test "parse rejects malformed commands and arity" {
    try testing.expectError(error.NeedMoreParams, parse(""));
    try testing.expectError(error.NeedMoreParams, parse("CHANHISTPOLICY"));
    try testing.expectError(error.UnknownCommand, parse("CHATHISTORY LATEST #zig * 10"));
    try testing.expectError(error.TooManyParams, parse("CHANHISTPOLICY #zig GET ops extra"));
    try testing.expectError(error.EmptyUpdate, parse("CHANHISTPOLICY #zig SET"));
    try testing.expectError(error.InvalidParams, parse("CHANHISTPOLICY #zig SET ops"));
    try testing.expectError(error.InvalidParams, parse("CHANHISTPOLICY #zig ops on"));
}

test "parse rejects invalid fields values and duplicates" {
    try testing.expectError(error.InvalidField, parse("CHANHISTPOLICY #zig GET unknown"));
    try testing.expectError(error.InvalidValue, parse("CHANHISTPOLICY #zig SET ops maybe"));
    try testing.expectError(error.DuplicateField, parse("CHANHISTPOLICY #zig SET ops on OPS off"));
    try testing.expectError(error.DuplicateField, parse("CHANHISTPOLICY #zig +ops ops=false"));
}

test "channel validation accepts real channel targets and rejects bad targets" {
    try validateChannel("#zig", max_channel_bytes);
    try validateChannel("&local", max_channel_bytes);

    try testing.expectError(error.InvalidChannel, validateChannel("", max_channel_bytes));
    try testing.expectError(error.InvalidChannel, validateChannel("#", max_channel_bytes));
    try testing.expectError(error.InvalidChannel, validateChannel("zig", max_channel_bytes));
    try testing.expectError(error.InvalidChannel, validateChannel("#bad chan", max_channel_bytes));
    try testing.expectError(error.InvalidChannel, validateChannel("#bad,chan", max_channel_bytes));
    try testing.expectError(error.InvalidChannel, validateChannel("#bad:chan", max_channel_bytes));
    try testing.expectError(error.InvalidChannel, validateChannel("#bad\rchan", max_channel_bytes));
}

test "parse options enforce custom channel length" {
    try testing.expectError(error.InvalidChannel, parseWithOptions("CHANHISTPOLICY #abcd", .{ .max_channel_len = 4 }));
    _ = try parseWithOptions("CHANHISTPOLICY #abc", .{ .max_channel_len = 4 });
}

test "numeric mappings use real IRC numerics" {
    try testing.expectEqual(Numeric.ERR_UNKNOWNCOMMAND, numericForParseError(error.UnknownCommand));
    try testing.expectEqual(Numeric.ERR_NOSUCHCHANNEL, numericForParseError(error.InvalidChannel));
    try testing.expectEqual(Numeric.ERR_NEEDMOREPARAMS, numericForParseError(error.InvalidValue));
    try testing.expectEqual(Numeric.ERR_CHANOPRIVSNEEDED, numericForAccessError(error.ChanopPrivsNeeded));
}

test "access helper returns channel-operator numeric path" {
    try requireHistoryAccess(.{ .ops = false }, false);
    try requireHistoryAccess(.{ .ops = true }, true);
    try testing.expectError(error.ChanopPrivsNeeded, requireHistoryAccess(.{ .ops = true }, false));
}

test "parsed update applies to registry" {
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();

    const request = try parse("CHANHISTPOLICY #hist +ops +playback_on_join");
    switch (request) {
        .set => |update| {
            const policy = try registry.apply(update);
            try testing.expect(policy.ops);
            try testing.expect(policy.playback_on_join);
        },
        else => return error.TestExpectedEqual,
    }
}
