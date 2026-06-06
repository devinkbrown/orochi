//! WATCH command state and parser.
//!
//! This module tracks per-watcher nick lists plus a reverse index keyed by
//! normalized nick, so nick presence changes can find interested watchers
//! without scanning every client.
const std = @import("std");

/// Stable per-client identifier used by the WATCH store.
pub const WatcherId = []const u8;

/// WATCH numeric replies and errors.
pub const WatchNumeric = enum(u16) {
    RPL_LOGON = 600,
    RPL_LOGOFF = 601,
    RPL_WATCHOFF = 602,
    RPL_WATCHSTAT = 603,
    RPL_NOWON = 604,
    RPL_NOWOFF = 605,
    RPL_ENDOFWATCH = 607,
    ERR_TOOMANYWATCH = 512,

    /// Return the integer IRC numeric code.
    pub fn code(self: WatchNumeric) u16 {
        return @intFromEnum(self);
    }

    /// Format the numeric as a three-digit IRC code into caller-owned storage.
    pub fn format(self: WatchNumeric, buf: []u8) []const u8 {
        if (buf.len < 3) return buf[0..0];
        const value = self.code();
        buf[0] = @as(u8, '0') + @as(u8, @intCast((value / 100) % 10));
        buf[1] = @as(u8, '0') + @as(u8, @intCast((value / 10) % 10));
        buf[2] = @as(u8, '0') + @as(u8, @intCast(value % 10));
        return buf[0..3];
    }
};

/// WATCH storage and parser bounds.
pub const Params = struct {
    max_watchers: usize = 1024,
    max_entries_per_watcher: usize = 64,
    max_watcher_bytes: usize = 128,
    max_nick_bytes: usize = 64,
    max_ops: usize = 32,
};

/// WATCH parser and store errors.
pub const WatchError = std.mem.Allocator.Error || error{
    MissingParameter,
    TooManyOperations,
    InvalidWatcher,
    WatcherTooLong,
    InvalidNick,
    NickTooLong,
    TooManyWatch,
    WatchExists,
    WatchNot,
    OutputTooSmall,
};

/// Parsed WATCH operation kind.
pub const WatchAction = enum {
    add,
    remove,
    clear,
    stat,
    list,
};

/// One parsed WATCH operation.
pub const WatchOperation = struct {
    action: WatchAction,
    nick: []const u8 = "",
};

/// Fixed-capacity parsed WATCH command storage.
pub fn ParsedCommand(comptime params: Params) type {
    comptime {
        if (params.max_ops == 0) @compileError("WATCH parser needs operation storage");
    }

    return struct {
        const Self = @This();

        operations: [params.max_ops]WatchOperation = undefined,
        count: usize = 0,

        /// Append one parsed operation.
        pub fn append(self: *Self, op: WatchOperation) WatchError!void {
            if (self.count >= self.operations.len) return error.TooManyOperations;
            self.operations[self.count] = op;
            self.count += 1;
        }

        /// Return the parsed operations in input order.
        pub fn slice(self: *const Self) []const WatchOperation {
            return self.operations[0..self.count];
        }
    };
}

/// Create a WATCH store type with compile-time storage limits.
pub fn WatchList(comptime params: Params) type {
    comptime {
        if (params.max_watchers == 0) @compileError("WATCH store needs watcher storage");
        if (params.max_entries_per_watcher == 0) @compileError("WATCH lists need entry storage");
        if (params.max_watcher_bytes == 0) @compileError("WATCH watcher ids need storage");
        if (params.max_nick_bytes == 0) @compileError("WATCH nick keys need storage");
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        watchers: std.StringHashMap(WatcherState),
        reverse: std.StringHashMap(ReverseState),
        watcher_count: usize = 0,

        const WatcherState = struct {
            nicks: std.StringHashMap([]u8),
            count: usize = 0,

            fn init(allocator: std.mem.Allocator) WatcherState {
                return .{ .nicks = std.StringHashMap([]u8).init(allocator) };
            }

            fn deinit(self: *WatcherState, allocator: std.mem.Allocator) void {
                var it = self.nicks.iterator();
                while (it.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    allocator.free(entry.value_ptr.*);
                }
                self.nicks.deinit();
                self.* = undefined;
            }
        };

        const ReverseState = struct {
            watchers: std.StringHashMap(void),
            count: usize = 0,

            fn init(allocator: std.mem.Allocator) ReverseState {
                return .{ .watchers = std.StringHashMap(void).init(allocator) };
            }

            fn deinit(self: *ReverseState, allocator: std.mem.Allocator) void {
                var it = self.watchers.iterator();
                while (it.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                }
                self.watchers.deinit();
                self.* = undefined;
            }
        };

        /// Initialize an empty WATCH store.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .watchers = std.StringHashMap(WatcherState).init(allocator),
                .reverse = std.StringHashMap(ReverseState).init(allocator),
            };
        }

        /// Free all memory owned by the WATCH store.
        pub fn deinit(self: *Self) void {
            self.clearAll();
            self.watchers.deinit();
            self.reverse.deinit();
            self.* = undefined;
        }

        /// Add `nick` to `watcher`'s WATCH list.
        pub fn add(self: *Self, watcher: WatcherId, nick: []const u8) WatchError!void {
            try validateWatcherWith(params, watcher);
            var nick_buf: [params.max_nick_bytes]u8 = undefined;
            const nick_key = try normalizeNickWith(params, nick, &nick_buf);

            const was_new_watcher = !self.watchers.contains(watcher);
            var state = try self.getOrCreateWatcher(watcher);
            errdefer if (was_new_watcher) self.removeEmptyWatcher(watcher);

            if (state.nicks.contains(nick_key)) return error.WatchExists;
            if (state.count >= params.max_entries_per_watcher) return error.TooManyWatch;

            const owned_key = try self.allocator.dupe(u8, nick_key);
            errdefer self.allocator.free(owned_key);
            const owned_nick = try self.allocator.dupe(u8, nick);
            errdefer self.allocator.free(owned_nick);

            try state.nicks.putNoClobber(owned_key, owned_nick);
            state.count += 1;
            errdefer {
                const removed = state.nicks.fetchRemove(nick_key).?;
                self.allocator.free(removed.key);
                self.allocator.free(removed.value);
                state.count -= 1;
            }

            try self.addReverse(nick_key, watcher);
        }

        /// Remove `nick` from `watcher`'s WATCH list.
        pub fn remove(self: *Self, watcher: WatcherId, nick: []const u8) WatchError!void {
            try validateWatcherWith(params, watcher);
            var nick_buf: [params.max_nick_bytes]u8 = undefined;
            const nick_key = try normalizeNickWith(params, nick, &nick_buf);
            var state = self.watchers.getPtr(watcher) orelse return error.WatchNot;

            const removed = state.nicks.fetchRemove(nick_key) orelse return error.WatchNot;
            self.removeReverse(nick_key, watcher);
            self.allocator.free(removed.key);
            self.allocator.free(removed.value);
            state.count -= 1;

            if (state.count == 0) {
                var removed_watcher = self.watchers.fetchRemove(watcher).?;
                self.allocator.free(removed_watcher.key);
                removed_watcher.value.deinit(self.allocator);
                self.watcher_count -= 1;
            }
        }

        /// Clear every watched nick for `watcher`.
        pub fn clear(self: *Self, watcher: WatcherId) void {
            const removed_watcher = self.watchers.fetchRemove(watcher) orelse return;
            var state = removed_watcher.value;

            var it = state.nicks.iterator();
            while (it.next()) |entry| {
                self.removeReverse(entry.key_ptr.*, watcher);
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            state.nicks.deinit();
            self.allocator.free(removed_watcher.key);
            self.watcher_count -= 1;
        }

        /// Copy `watcher`'s watched nicks into caller-owned output storage.
        pub fn list(self: *const Self, watcher: WatcherId, out: [][]const u8) WatchError![]const []const u8 {
            try validateWatcherWith(params, watcher);
            const state = self.watchers.getPtr(watcher) orelse return out[0..0];
            if (out.len < state.count) return error.OutputTooSmall;

            var index: usize = 0;
            var it = state.nicks.iterator();
            while (it.next()) |entry| {
                out[index] = entry.value_ptr.*;
                index += 1;
            }
            return out[0..index];
        }

        /// Return the number of nicks watched by `watcher`.
        pub fn count(self: *const Self, watcher: WatcherId) usize {
            const state = self.watchers.getPtr(watcher) orelse return 0;
            return state.count;
        }

        /// Copy watchers interested in `nick` into caller-owned output storage.
        pub fn watchersOf(self: *const Self, nick: []const u8, out: []WatcherId) WatchError![]const WatcherId {
            var nick_buf: [params.max_nick_bytes]u8 = undefined;
            const nick_key = try normalizeNickWith(params, nick, &nick_buf);
            const reverse_state = self.reverse.getPtr(nick_key) orelse return out[0..0];
            if (out.len < reverse_state.count) return error.OutputTooSmall;

            var index: usize = 0;
            var it = reverse_state.watchers.iterator();
            while (it.next()) |entry| {
                out[index] = entry.key_ptr.*;
                index += 1;
            }
            return out[0..index];
        }

        fn clearAll(self: *Self) void {
            var watcher_it = self.watchers.iterator();
            while (watcher_it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.watchers.clearRetainingCapacity();

            var reverse_it = self.reverse.iterator();
            while (reverse_it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.reverse.clearRetainingCapacity();
            self.watcher_count = 0;
        }

        fn getOrCreateWatcher(self: *Self, watcher: WatcherId) WatchError!*WatcherState {
            if (self.watchers.getPtr(watcher)) |state| return state;
            if (self.watcher_count >= params.max_watchers) return error.TooManyWatch;

            const owned_watcher = try self.allocator.dupe(u8, watcher);
            errdefer self.allocator.free(owned_watcher);

            try self.watchers.putNoClobber(owned_watcher, WatcherState.init(self.allocator));
            self.watcher_count += 1;
            return self.watchers.getPtr(owned_watcher).?;
        }

        fn addReverse(self: *Self, nick_key: []const u8, watcher: WatcherId) WatchError!void {
            const created_reverse = !self.reverse.contains(nick_key);
            if (created_reverse) {
                const owned_nick = try self.allocator.dupe(u8, nick_key);
                errdefer self.allocator.free(owned_nick);
                try self.reverse.putNoClobber(owned_nick, ReverseState.init(self.allocator));
            }
            errdefer if (created_reverse) self.removeEmptyReverse(nick_key);

            var reverse_state = self.reverse.getPtr(nick_key).?;
            if (reverse_state.watchers.contains(watcher)) return;

            const owned_watcher = try self.allocator.dupe(u8, watcher);
            errdefer self.allocator.free(owned_watcher);
            try reverse_state.watchers.putNoClobber(owned_watcher, {});
            reverse_state.count += 1;
        }

        fn removeReverse(self: *Self, nick_key: []const u8, watcher: WatcherId) void {
            var reverse_state = self.reverse.getPtr(nick_key) orelse return;
            const removed = reverse_state.watchers.fetchRemove(watcher) orelse return;
            self.allocator.free(removed.key);
            reverse_state.count -= 1;

            if (reverse_state.count == 0) {
                var removed_reverse = self.reverse.fetchRemove(nick_key).?;
                self.allocator.free(removed_reverse.key);
                removed_reverse.value.deinit(self.allocator);
            }
        }

        fn removeEmptyWatcher(self: *Self, watcher: WatcherId) void {
            const state = self.watchers.getPtr(watcher) orelse return;
            if (state.count != 0) return;

            var removed = self.watchers.fetchRemove(watcher).?;
            self.allocator.free(removed.key);
            removed.value.deinit(self.allocator);
            self.watcher_count -= 1;
        }

        fn removeEmptyReverse(self: *Self, nick_key: []const u8) void {
            const state = self.reverse.getPtr(nick_key) orelse return;
            if (state.count != 0) return;

            var removed = self.reverse.fetchRemove(nick_key).?;
            self.allocator.free(removed.key);
            removed.value.deinit(self.allocator);
        }
    };
}

/// Default WATCH store using production-sized limits.
pub const DefaultList = WatchList(.{});

/// Parse WATCH arguments using default parser bounds.
pub fn parse(args: []const []const u8) WatchError!ParsedCommand(.{}) {
    return parseBounded(.{}, args);
}

/// Parse WATCH arguments using caller-provided parser bounds.
pub fn parseBounded(comptime bounds: Params, args: []const []const u8) WatchError!ParsedCommand(bounds) {
    if (args.len == 0) return error.MissingParameter;

    var parsed = ParsedCommand(bounds){};
    for (args) |arg| {
        try parseTokenList(bounds, arg, &parsed);
    }
    return parsed;
}

/// Validate a watcher id against caller-provided limits.
pub fn validateWatcherWith(comptime params: Params, watcher: WatcherId) WatchError!void {
    if (watcher.len == 0) return error.InvalidWatcher;
    if (watcher.len > params.max_watcher_bytes) return error.WatcherTooLong;
    for (watcher) |byte| {
        if (byte == 0 or byte <= 0x20 or byte == 0x7f) return error.InvalidWatcher;
    }
}

/// Validate a nick against caller-provided limits.
pub fn validateNickWith(comptime params: Params, nick: []const u8) WatchError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |byte| {
        if (!validNickByte(byte)) return error.InvalidNick;
    }
}

fn parseTokenList(comptime bounds: Params, arg: []const u8, parsed: *ParsedCommand(bounds)) WatchError!void {
    var start: usize = 0;
    while (start <= arg.len) {
        const end = std.mem.indexOfScalarPos(u8, arg, start, ',') orelse arg.len;
        try parseOne(bounds, arg[start..end], parsed);
        if (end == arg.len) break;
        start = end + 1;
    }
}

fn parseOne(comptime bounds: Params, raw: []const u8, parsed: *ParsedCommand(bounds)) WatchError!void {
    if (raw.len == 0) return error.MissingParameter;

    if (raw.len == 1) {
        const action: ?WatchAction = switch (raw[0]) {
            'C', 'c' => .clear,
            'S', 's' => .stat,
            'L', 'l' => .list,
            else => null,
        };
        if (action) |kind| {
            try parsed.append(.{ .action = kind });
            return;
        }
    }

    const action: WatchAction = switch (raw[0]) {
        '+' => .add,
        '-' => .remove,
        else => return error.MissingParameter,
    };
    const nick = raw[1..];
    try validateNickWith(bounds, nick);
    try parsed.append(.{ .action = action, .nick = nick });
}

fn normalizeNickWith(comptime params: Params, nick: []const u8, out: *[params.max_nick_bytes]u8) WatchError![]const u8 {
    try validateNickWith(params, nick);
    for (nick, 0..) |byte, index| {
        out[index] = std.ascii.toLower(byte);
    }
    return out[0..nick.len];
}

fn validNickByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '[', ']', '\\', '`', '_', '^', '{', '|', '}', '-' => true,
        else => false,
    };
}

fn expectContains(haystack: []const []const u8, needle: []const u8) !void {
    for (haystack) |candidate| {
        if (std.mem.eql(u8, candidate, needle)) return;
    }
    return error.TestExpectedEqual;
}

test "WATCH numeric code and format produce canonical values" {
    // Arrange.
    var buf: [3]u8 = undefined;

    // Act.
    const logon_code = WatchNumeric.RPL_LOGON.code();
    const too_many = WatchNumeric.ERR_TOOMANYWATCH.format(&buf);

    // Assert.
    try std.testing.expectEqual(@as(u16, 600), logon_code);
    try std.testing.expectEqualStrings("512", too_many);
}

test "add remove list and count maintain a watcher list" {
    // Arrange.
    var list_store = DefaultList.init(std.testing.allocator);
    defer list_store.deinit();

    // Act.
    try list_store.add("client-a", "Alice");
    try list_store.add("client-a", "Bob");
    var out: [2][]const u8 = undefined;
    const watched = try list_store.list("client-a", &out);

    // Assert.
    try std.testing.expectEqual(@as(usize, 2), list_store.count("client-a"));
    try expectContains(watched, "Alice");
    try expectContains(watched, "Bob");

    try list_store.remove("client-a", "alice");
    try std.testing.expectEqual(@as(usize, 1), list_store.count("client-a"));
    try std.testing.expectError(error.WatchNot, list_store.remove("client-a", "Alice"));
}

test "reverse lookup stays correct after add remove and clear" {
    // Arrange.
    var list_store = DefaultList.init(std.testing.allocator);
    defer list_store.deinit();

    // Act.
    try list_store.add("client-a", "Alice");
    try list_store.add("client-b", "alice");
    try list_store.add("client-c", "Bob");

    var out: [3]WatcherId = undefined;
    const alice_watchers = try list_store.watchersOf("ALICE", &out);

    // Assert.
    try std.testing.expectEqual(@as(usize, 2), alice_watchers.len);
    try expectContains(alice_watchers, "client-a");
    try expectContains(alice_watchers, "client-b");

    try list_store.remove("client-a", "alice");
    const remaining = try list_store.watchersOf("Alice", &out);
    try std.testing.expectEqual(@as(usize, 1), remaining.len);
    try std.testing.expectEqualStrings("client-b", remaining[0]);

    list_store.clear("client-b");
    const none = try list_store.watchersOf("alice", &out);
    try std.testing.expectEqual(@as(usize, 0), none.len);
}

test "duplicate watches are rejected without changing indexes" {
    // Arrange.
    var list_store = DefaultList.init(std.testing.allocator);
    defer list_store.deinit();

    // Act.
    try list_store.add("client-a", "Alice");
    const duplicate = list_store.add("client-a", "alice");

    // Assert.
    try std.testing.expectError(error.WatchExists, duplicate);
    try std.testing.expectEqual(@as(usize, 1), list_store.count("client-a"));

    var out: [1]WatcherId = undefined;
    const watchers = try list_store.watchersOf("ALICE", &out);
    try std.testing.expectEqual(@as(usize, 1), watchers.len);
    try std.testing.expectEqualStrings("client-a", watchers[0]);
}

test "watcher and entry limits return too many watch" {
    // Arrange.
    const Small = WatchList(.{ .max_watchers = 1, .max_entries_per_watcher = 1 });
    var list_store = Small.init(std.testing.allocator);
    defer list_store.deinit();

    // Act and assert.
    try list_store.add("client-a", "Alice");
    try std.testing.expectError(error.TooManyWatch, list_store.add("client-a", "Bob"));
    try std.testing.expectError(error.TooManyWatch, list_store.add("client-b", "Carol"));
}

test "output buffers must fit list and reverse results" {
    // Arrange.
    var list_store = DefaultList.init(std.testing.allocator);
    defer list_store.deinit();

    // Act.
    try list_store.add("client-a", "Alice");
    try list_store.add("client-a", "Bob");
    try list_store.add("client-b", "Alice");

    var nick_out: [1][]const u8 = undefined;
    var watcher_out: [1]WatcherId = undefined;

    // Assert.
    try std.testing.expectError(error.OutputTooSmall, list_store.list("client-a", &nick_out));
    try std.testing.expectError(error.OutputTooSmall, list_store.watchersOf("alice", &watcher_out));
}

test "parse mixed add remove clear stat and list tokens" {
    // Arrange.
    const args = [_][]const u8{ "+alice,-bob", "C", "S", "L", "+Carol" };

    // Act.
    const parsed = try parse(&args);
    const ops = parsed.slice();

    // Assert.
    try std.testing.expectEqual(@as(usize, 6), ops.len);
    try std.testing.expectEqual(WatchAction.add, ops[0].action);
    try std.testing.expectEqualStrings("alice", ops[0].nick);
    try std.testing.expectEqual(WatchAction.remove, ops[1].action);
    try std.testing.expectEqualStrings("bob", ops[1].nick);
    try std.testing.expectEqual(WatchAction.clear, ops[2].action);
    try std.testing.expectEqual(WatchAction.stat, ops[3].action);
    try std.testing.expectEqual(WatchAction.list, ops[4].action);
    try std.testing.expectEqual(WatchAction.add, ops[5].action);
    try std.testing.expectEqualStrings("Carol", ops[5].nick);
}

test "parse rejects missing invalid and overflowing operations" {
    // Arrange.
    const SmallParsed = struct {
        fn parseSmall(args: []const []const u8) WatchError!ParsedCommand(.{ .max_ops = 2 }) {
            return parseBounded(.{ .max_ops = 2 }, args);
        }
    };

    // Act and assert.
    try std.testing.expectError(error.MissingParameter, parse(&.{}));
    try std.testing.expectError(error.InvalidNick, parse(&.{"+bad!"}));
    try std.testing.expectError(error.TooManyOperations, SmallParsed.parseSmall(&.{ "+a", "-b", "L" }));
}
