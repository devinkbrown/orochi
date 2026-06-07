const std = @import("std");
const numeric = @import("numeric.zig");
const limits_config = @import("limits_config.zig");

pub const AcceptNumeric = enum(u16) {
    RPL_ACCEPTLIST = 281,
    RPL_ENDOFACCEPT = 282,
    ERR_ACCEPTFULL = 456,
    ERR_ACCEPTEXIST = 457,
    ERR_ACCEPTNOT = 458,

    fn known(self: AcceptNumeric) numeric.Numeric {
        return switch (self) {
            .RPL_ACCEPTLIST => .RPL_ACCEPTLIST,
            .RPL_ENDOFACCEPT => .RPL_ENDOFACCEPT,
            .ERR_ACCEPTFULL => .ERR_ACCEPTFULL,
            .ERR_ACCEPTEXIST => .ERR_ACCEPTEXIST,
            .ERR_ACCEPTNOT => .ERR_ACCEPTNOT,
        };
    }
};

pub const Params = struct {
    max_owners: usize = 1024,
    max_entries_per_owner: usize = 64,
    max_owner_bytes: usize = 128,
    max_nick_bytes: usize = 64,
    max_ops: usize = 32,
    max_server_name_bytes: usize = 255,
    max_line_bytes: usize = 512,

    /// Derive `Params` from the central policy limits (config-driven).
    /// `max_line_bytes` is a wire-framing budget and keeps its default.
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_owners = limits.accept_max_owners,
            .max_entries_per_owner = limits.accept_entries_per_owner,
            .max_nick_bytes = limits.nick_len,
            .max_server_name_bytes = limits.server_name_len,
        };
    }
};

pub const AcceptError = std.mem.Allocator.Error || error{
    MissingParameter,
    TooManyParameters,
    TooManyOperations,
    InvalidOwner,
    OwnerTooLong,
    InvalidNick,
    NickTooLong,
    InvalidServerName,
    ServerNameTooLong,
    AcceptFull,
    AcceptExists,
    AcceptNot,
    OutputTooSmall,
};

pub const Action = enum { add, remove, list };

pub const Operation = struct {
    action: Action,
    nick: []const u8 = "",
};

pub fn ParsedCommand(comptime params: Params) type {
    comptime {
        if (params.max_ops == 0) @compileError("ACCEPT parser needs operation storage");
    }

    return struct {
        const Self = @This();

        operations: [params.max_ops]Operation = undefined,
        count: usize = 0,

        pub fn append(self: *Self, op: Operation) AcceptError!void {
            if (self.count >= self.operations.len) return error.TooManyOperations;
            self.operations[self.count] = op;
            self.count += 1;
        }

        pub fn slice(self: *const Self) []const Operation {
            return self.operations[0..self.count];
        }
    };
}

pub fn AcceptList(comptime params: Params) type {
    comptime {
        if (params.max_owners == 0) @compileError("ACCEPT store needs owner storage");
        if (params.max_entries_per_owner == 0) @compileError("ACCEPT lists need entry storage");
        if (params.max_owner_bytes == 0) @compileError("ACCEPT owner ids need storage");
        if (params.max_nick_bytes == 0) @compileError("ACCEPT nick keys need storage");
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        owners: std.StringHashMap(OwnerState),
        owner_count: usize = 0,

        const OwnerState = struct {
            nicks: std.StringHashMap([]u8),
            count: usize = 0,

            fn init(allocator: std.mem.Allocator) OwnerState {
                return .{ .nicks = std.StringHashMap([]u8).init(allocator) };
            }

            fn deinit(self: *OwnerState, allocator: std.mem.Allocator) void {
                var it = self.nicks.iterator();
                while (it.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    allocator.free(entry.value_ptr.*);
                }
                self.nicks.deinit();
                self.* = undefined;
            }
        };

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .owners = std.StringHashMap(OwnerState).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.clear();
            self.owners.deinit();
            self.* = undefined;
        }

        pub fn clear(self: *Self) void {
            var it = self.owners.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.owners.clearRetainingCapacity();
            self.owner_count = 0;
        }

        pub fn add(self: *Self, owner: []const u8, nick: []const u8) AcceptError!void {
            var nick_buf: [params.max_nick_bytes]u8 = undefined;
            const nick_key = try normalizeNickWith(params, nick, &nick_buf);
            var state = try self.getOrCreateOwner(owner);

            if (state.nicks.contains(nick_key)) return error.AcceptExists;
            if (state.count >= params.max_entries_per_owner) return error.AcceptFull;

            const owned_key = try self.allocator.dupe(u8, nick_key);
            errdefer self.allocator.free(owned_key);
            const owned_nick = try self.allocator.dupe(u8, nick);
            errdefer self.allocator.free(owned_nick);

            try state.nicks.putNoClobber(owned_key, owned_nick);
            state.count += 1;
        }

        pub fn remove(self: *Self, owner: []const u8, nick: []const u8) AcceptError!void {
            try validateOwnerWith(params, owner);
            var nick_buf: [params.max_nick_bytes]u8 = undefined;
            const nick_key = try normalizeNickWith(params, nick, &nick_buf);
            var state = self.owners.getPtr(owner) orelse return error.AcceptNot;

            const removed = state.nicks.fetchRemove(nick_key) orelse return error.AcceptNot;
            self.allocator.free(removed.key);
            self.allocator.free(removed.value);
            state.count -= 1;

            if (state.count == 0) {
                var removed_owner = self.owners.fetchRemove(owner).?;
                self.allocator.free(removed_owner.key);
                removed_owner.value.deinit(self.allocator);
                self.owner_count -= 1;
            }
        }

        pub fn contains(self: *const Self, owner: []const u8, nick: []const u8) AcceptError!bool {
            try validateOwnerWith(params, owner);
            var nick_buf: [params.max_nick_bytes]u8 = undefined;
            const nick_key = try normalizeNickWith(params, nick, &nick_buf);
            const state = self.owners.getPtr(owner) orelse return false;
            return state.nicks.contains(nick_key);
        }

        pub fn list(self: *const Self, owner: []const u8, out: [][]const u8) AcceptError![]const []const u8 {
            try validateOwnerWith(params, owner);
            const state = self.owners.getPtr(owner) orelse return out[0..0];
            if (out.len < state.count) return error.OutputTooSmall;

            var index: usize = 0;
            var it = state.nicks.iterator();
            while (it.next()) |entry| {
                out[index] = entry.value_ptr.*;
                index += 1;
            }
            return out[0..index];
        }

        fn getOrCreateOwner(self: *Self, owner: []const u8) AcceptError!*OwnerState {
            try validateOwnerWith(params, owner);
            if (self.owners.getPtr(owner)) |state| return state;
            if (self.owner_count >= params.max_owners) return error.AcceptFull;

            const owned_owner = try self.allocator.dupe(u8, owner);
            errdefer self.allocator.free(owned_owner);

            try self.owners.putNoClobber(owned_owner, OwnerState.init(self.allocator));
            self.owner_count += 1;
            return self.owners.getPtr(owned_owner).?;
        }
    };
}

pub const DefaultList = AcceptList(.{});

pub fn parse(params: []const []const u8) AcceptError!ParsedCommand(.{}) {
    return parseBounded(.{}, params);
}

pub fn parseBounded(comptime bounds: Params, params: []const []const u8) AcceptError!ParsedCommand(bounds) {
    if (params.len == 0) return error.MissingParameter;

    var parsed = ParsedCommand(bounds){};
    for (params) |param| {
        try parseTokenList(bounds, param, &parsed);
    }
    return parsed;
}

pub fn parseLine(line: []const u8) AcceptError!ParsedCommand(.{}) {
    return parseLineBounded(.{}, line);
}

pub fn parseLineBounded(comptime bounds: Params, line: []const u8) AcceptError!ParsedCommand(bounds) {
    var tokens: [bounds.max_ops + 1][]const u8 = undefined;
    var count: usize = 0;
    var it = std.mem.tokenizeAny(u8, line, " \r\n");

    const command = it.next() orelse return error.MissingParameter;
    if (!std.ascii.eqlIgnoreCase(command, "ACCEPT")) return error.MissingParameter;

    while (it.next()) |token| {
        if (count >= tokens.len - 1) return error.TooManyParameters;
        tokens[count] = token;
        count += 1;
    }
    return parseBounded(bounds, tokens[0..count]);
}

pub fn buildAcceptListReplyWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    nick: []const u8,
) AcceptError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, requester_nick);
    try validateNickWith(params, nick);

    var writer = BufferWriter.init(out);
    try writeNumericHeader(&writer, .RPL_ACCEPTLIST, server_name, requester_nick);
    try writer.appendByte(' ');
    try writer.appendBytes(nick);
    try writer.appendBytes(" :is on your accept list\r\n");
    if (writer.len > params.max_line_bytes) return error.OutputTooSmall;
    return writer.slice();
}

pub fn buildEndOfAcceptReplyWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
) AcceptError![]const u8 {
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, requester_nick);

    var writer = BufferWriter.init(out);
    try writeNumericHeader(&writer, .RPL_ENDOFACCEPT, server_name, requester_nick);
    try writer.appendBytes(" :End of ACCEPT list\r\n");
    if (writer.len > params.max_line_bytes) return error.OutputTooSmall;
    return writer.slice();
}

pub fn buildAcceptErrorReplyWith(
    comptime params: Params,
    out: []u8,
    server_name: []const u8,
    requester_nick: []const u8,
    err_numeric: AcceptNumeric,
    nick: []const u8,
) AcceptError![]const u8 {
    switch (err_numeric) {
        .ERR_ACCEPTFULL, .ERR_ACCEPTEXIST, .ERR_ACCEPTNOT => {},
        .RPL_ACCEPTLIST, .RPL_ENDOFACCEPT => return error.InvalidNick,
    }
    try validateServerNameWith(params, server_name);
    try validateNickWith(params, requester_nick);
    try validateNickWith(params, nick);

    var writer = BufferWriter.init(out);
    try writeNumericHeader(&writer, err_numeric, server_name, requester_nick);
    try writer.appendByte(' ');
    try writer.appendBytes(nick);
    try writer.appendBytes(switch (err_numeric) {
        .ERR_ACCEPTFULL => " :Accept list is full\r\n",
        .ERR_ACCEPTEXIST => " :is already on your accept list\r\n",
        .ERR_ACCEPTNOT => " :is not on your accept list\r\n",
        else => unreachable,
    });
    if (writer.len > params.max_line_bytes) return error.OutputTooSmall;
    return writer.slice();
}

fn parseTokenList(comptime bounds: Params, param: []const u8, parsed: *ParsedCommand(bounds)) AcceptError!void {
    var start: usize = 0;
    while (start <= param.len) {
        const end = std.mem.indexOfScalarPos(u8, param, start, ',') orelse param.len;
        try parseOne(bounds, param[start..end], parsed);
        if (end == param.len) break;
        start = end + 1;
    }
}

fn parseOne(comptime bounds: Params, raw: []const u8, parsed: *ParsedCommand(bounds)) AcceptError!void {
    if (raw.len == 0) return error.MissingParameter;
    if (std.mem.eql(u8, raw, "*")) {
        try parsed.append(.{ .action = .list });
        return;
    }

    const action: Action = switch (raw[0]) {
        '+' => .add,
        '-' => .remove,
        else => return error.MissingParameter,
    };
    const nick = raw[1..];
    try validateNickWith(bounds, nick);
    try parsed.append(.{ .action = action, .nick = nick });
}

pub fn validateOwnerWith(comptime params: Params, owner: []const u8) AcceptError!void {
    if (owner.len == 0) return error.InvalidOwner;
    if (owner.len > params.max_owner_bytes) return error.OwnerTooLong;
    for (owner) |byte| {
        if (byte == 0 or byte <= 0x20 or byte == 0x7f) return error.InvalidOwner;
    }
}

pub fn validateNickWith(comptime params: Params, nick: []const u8) AcceptError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |byte| {
        if (!validNickByte(byte)) return error.InvalidNick;
    }
}

fn normalizeNickWith(comptime params: Params, nick: []const u8, out: *[params.max_nick_bytes]u8) AcceptError![]const u8 {
    try validateNickWith(params, nick);
    for (nick, 0..) |byte, index| {
        out[index] = std.ascii.toLower(byte);
    }
    return out[0..nick.len];
}

fn validateServerNameWith(comptime params: Params, server_name: []const u8) AcceptError!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > params.max_server_name_bytes) return error.ServerNameTooLong;
    for (server_name) |byte| {
        if (!validServerNameByte(byte)) return error.InvalidServerName;
    }
}

fn writeNumericHeader(writer: *BufferWriter, reply_numeric: AcceptNumeric, server_name: []const u8, requester_nick: []const u8) AcceptError!void {
    var code_buf: [3]u8 = undefined;
    const code = numeric.formatCode(reply_numeric.known(), &code_buf);

    try writer.appendByte(':');
    try writer.appendBytes(server_name);
    try writer.appendByte(' ');
    try writer.appendBytes(code);
    try writer.appendByte(' ');
    try writer.appendBytes(requester_nick);
}

fn validNickByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '[', ']', '\\', '`', '_', '^', '{', '|', '}', '-' => true,
        else => false,
    };
}

fn validServerNameByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', ':', '[', ']' => true,
        else => false,
    };
}

const BufferWriter = struct {
    out: []u8,
    len: usize = 0,

    fn init(out: []u8) BufferWriter {
        return .{ .out = out };
    }

    fn slice(self: *const BufferWriter) []const u8 {
        return self.out[0..self.len];
    }

    fn appendBytes(self: *BufferWriter, bytes: []const u8) AcceptError!void {
        if (self.len > self.out.len or bytes.len > self.out.len - self.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *BufferWriter, byte: u8) AcceptError!void {
        if (self.len >= self.out.len) return error.OutputTooSmall;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

test "add remove contains" {
    var list = DefaultList.init(std.testing.allocator);
    defer list.deinit();

    try list.add("client-a", "Alice");
    try std.testing.expect(try list.contains("client-a", "alice"));
    try std.testing.expect(try list.contains("client-a", "ALICE"));
    try std.testing.expect(!try list.contains("client-a", "bob"));

    try list.remove("client-a", "aLiCe");
    try std.testing.expect(!try list.contains("client-a", "Alice"));
    try std.testing.expectError(error.AcceptNot, list.remove("client-a", "Alice"));
}

test "parse plus minus star forms" {
    const parsed = try parse(&.{"+alice,-bob,*"});
    const ops = parsed.slice();
    try std.testing.expectEqual(@as(usize, 3), ops.len);
    try std.testing.expectEqual(Action.add, ops[0].action);
    try std.testing.expectEqualStrings("alice", ops[0].nick);
    try std.testing.expectEqual(Action.remove, ops[1].action);
    try std.testing.expectEqualStrings("bob", ops[1].nick);
    try std.testing.expectEqual(Action.list, ops[2].action);

    const line = try parseLine("ACCEPT +carol,-dave,*\r\n");
    try std.testing.expectEqual(@as(usize, 3), line.slice().len);
}

test "list builder bytes" {
    var out: [256]u8 = undefined;
    const entry = try buildAcceptListReplyWith(.{}, &out, "irc.example.test", "dan", "alice");
    try std.testing.expectEqualStrings(":irc.example.test 281 dan alice :is on your accept list\r\n", entry);

    const end = try buildEndOfAcceptReplyWith(.{}, &out, "irc.example.test", "dan");
    try std.testing.expectEqualStrings(":irc.example.test 282 dan :End of ACCEPT list\r\n", end);

    const err = try buildAcceptErrorReplyWith(.{}, &out, "irc.example.test", "dan", .ERR_ACCEPTEXIST, "alice");
    try std.testing.expectEqualStrings(":irc.example.test 457 dan alice :is already on your accept list\r\n", err);
}

test "limit and duplicate handling" {
    const Small = AcceptList(.{ .max_owners = 1, .max_entries_per_owner = 1 });
    var list = Small.init(std.testing.allocator);
    defer list.deinit();

    try list.add("client-a", "Alice");
    try std.testing.expectError(error.AcceptExists, list.add("client-a", "alice"));
    try std.testing.expectError(error.AcceptFull, list.add("client-a", "Bob"));
    try std.testing.expectError(error.AcceptFull, list.add("client-b", "Carol"));
}

test "list API and no leak" {
    var list = DefaultList.init(std.testing.allocator);
    defer list.deinit();

    try list.add("client-a", "Alice");
    try list.add("client-a", "Bob");

    var out: [2][]const u8 = undefined;
    const nicks = try list.list("client-a", &out);
    try std.testing.expectEqual(@as(usize, 2), nicks.len);
    try std.testing.expect(try list.contains("client-a", nicks[0]));
    try std.testing.expect(try list.contains("client-a", nicks[1]));

    try list.remove("client-a", "alice");
    try list.remove("client-a", "bob");
}
