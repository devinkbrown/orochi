const std = @import("std");

/// Numeric replies used by the DCCALLOW command model.
///
/// These values follow the long-standing DCCALLOW numeric range used by IRC
/// daemon implementations: 617 for status, 618 for list entries, 619 for list
/// termination, and 620 for command help or informational text.
pub const DccAllowNumeric = enum(u16) {
    /// Reports the status of a DCCALLOW add or remove operation.
    RPL_DCCSTATUS = 617,
    /// Reports one nick currently present in a DCCALLOW list.
    RPL_DCCLIST = 618,
    /// Marks the end of a DCCALLOW list reply.
    RPL_ENDOFDCCLIST = 619,
    /// Reports DCCALLOW help or informational text.
    RPL_DCCINFO = 620,

    /// Returns the integer wire code for this numeric.
    pub fn code(self: DccAllowNumeric) u16 {
        return @intFromEnum(self);
    }

    /// Formats this numeric as a fixed-width three-byte decimal code.
    pub fn format(self: DccAllowNumeric, out: *[3]u8) []const u8 {
        const value = self.code();
        const hundreds: u8 = @intCast((value / 100) % 10);
        const tens: u8 = @intCast((value / 10) % 10);
        const ones: u8 = @intCast(value % 10);

        out[0] = '0' + hundreds;
        out[1] = '0' + tens;
        out[2] = '0' + ones;
        return out[0..];
    }
};

/// Compile-time bounds for a DCCALLOW list implementation.
pub const Params = struct {
    /// Maximum number of owners tracked by one store.
    max_owners: usize = 1024,
    /// Maximum number of allowed nicks per owner.
    max_entries_per_owner: usize = 64,
    /// Maximum owner identifier length in bytes.
    max_owner_bytes: usize = 128,
    /// Maximum nick length in bytes.
    max_nick_bytes: usize = 64,
    /// Maximum operations accepted by the parser.
    max_ops: usize = 32,
    /// Minimum accepted absolute expiry timestamp.
    min_expiry_timestamp: i64 = 0,
    /// Maximum accepted absolute expiry timestamp.
    max_expiry_timestamp: i64 = std.math.maxInt(i64),
};

/// Errors returned by DCCALLOW parsing and list operations.
pub const DccAllowError = std.mem.Allocator.Error || error{
    MissingParameter,
    TooManyOperations,
    InvalidOwner,
    OwnerTooLong,
    InvalidNick,
    NickTooLong,
    InvalidExpiry,
    DccAllowFull,
    OutputTooSmall,
};

/// A borrowed DCCALLOW operation produced by the parser.
pub const Action = enum {
    add,
    remove,
    list,
    help,
};

/// One parsed DCCALLOW operation.
pub const Operation = struct {
    /// Requested operation kind.
    action: Action,
    /// Borrowed nick parameter for add and remove operations.
    nick: []const u8 = "",
};

/// One listed DCCALLOW entry.
pub const Entry = struct {
    /// Stored display nick for the allowed sender.
    nick: []const u8,
    /// Absolute expiry timestamp, or null when the entry does not expire.
    expires_at: ?i64,
};

/// Returns a fixed-capacity parsed-command type for the provided bounds.
pub fn ParsedCommand(comptime params: Params) type {
    comptime {
        if (params.max_ops == 0) @compileError("DCCALLOW parser needs operation storage");
    }

    return struct {
        const Self = @This();

        operations: [params.max_ops]Operation = undefined,
        count: usize = 0,

        /// Appends one parsed operation.
        pub fn append(self: *Self, op: Operation) DccAllowError!void {
            if (self.count >= self.operations.len) return error.TooManyOperations;
            self.operations[self.count] = op;
            self.count += 1;
        }

        /// Returns the initialized operation slice.
        pub fn slice(self: *const Self) []const Operation {
            return self.operations[0..self.count];
        }
    };
}

/// Returns a DCCALLOW list type specialized for the provided bounds.
pub fn DccAllowListWith(comptime params: Params) type {
    comptime {
        if (params.max_owners == 0) @compileError("DCCALLOW store needs owner storage");
        if (params.max_entries_per_owner == 0) @compileError("DCCALLOW lists need entry storage");
        if (params.max_owner_bytes == 0) @compileError("DCCALLOW owner ids need storage");
        if (params.max_nick_bytes == 0) @compileError("DCCALLOW nick keys need storage");
        if (params.min_expiry_timestamp > params.max_expiry_timestamp) {
            @compileError("DCCALLOW expiry timestamp bounds are inverted");
        }
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        owners: std.StringHashMap(OwnerState),
        owner_count: usize = 0,

        const StoredEntry = struct {
            nick: []u8,
            expires_at: ?i64,
        };

        const OwnerState = struct {
            entries: std.StringHashMap(StoredEntry),
            count: usize = 0,

            fn init(allocator: std.mem.Allocator) OwnerState {
                return .{ .entries = std.StringHashMap(StoredEntry).init(allocator) };
            }

            fn deinit(self: *OwnerState, allocator: std.mem.Allocator) void {
                var it = self.entries.iterator();
                while (it.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    allocator.free(entry.value_ptr.nick);
                }
                self.entries.deinit();
                self.* = undefined;
            }

            fn removeByKey(self: *OwnerState, allocator: std.mem.Allocator, nick_key: []const u8) bool {
                const removed = self.entries.fetchRemove(nick_key) orelse return false;
                allocator.free(removed.key);
                allocator.free(removed.value.nick);
                self.count -= 1;
                return true;
            }

            fn pruneExpired(self: *OwnerState, allocator: std.mem.Allocator, now: i64) void {
                while (true) {
                    var expired_key: ?[]const u8 = null;
                    var it = self.entries.iterator();
                    while (it.next()) |entry| {
                        if (isExpired(entry.value_ptr.expires_at, now)) {
                            expired_key = entry.key_ptr.*;
                            break;
                        }
                    }

                    if (expired_key) |nick_key| {
                        _ = self.removeByKey(allocator, nick_key);
                    } else {
                        break;
                    }
                }
            }
        };

        /// Initializes an empty DCCALLOW list store.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .owners = std.StringHashMap(OwnerState).init(allocator),
            };
        }

        /// Frees all owners, entries, and map storage.
        pub fn deinit(self: *Self) void {
            self.clear();
            self.owners.deinit();
            self.* = undefined;
        }

        /// Removes every stored owner and entry while retaining map capacity.
        pub fn clear(self: *Self) void {
            var it = self.owners.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.owners.clearRetainingCapacity();
            self.owner_count = 0;
        }

        /// Adds or refreshes one allowed nick for an owner.
        pub fn add(self: *Self, owner: []const u8, nick: []const u8, expires_at: ?i64) DccAllowError!void {
            var nick_buf: [params.max_nick_bytes]u8 = undefined;
            const nick_key = try normalizeNickWith(params, nick, &nick_buf);
            try validateExpiryWith(params, expires_at);

            var state = try self.getOrCreateOwner(owner);
            if (state.entries.getPtr(nick_key)) |entry| {
                entry.expires_at = expires_at;
                return;
            }
            if (state.count >= params.max_entries_per_owner) return error.DccAllowFull;

            const owned_key = try self.allocator.dupe(u8, nick_key);
            errdefer self.allocator.free(owned_key);
            const owned_nick = try self.allocator.dupe(u8, nick);
            errdefer self.allocator.free(owned_nick);

            try state.entries.putNoClobber(owned_key, .{
                .nick = owned_nick,
                .expires_at = expires_at,
            });
            state.count += 1;
        }

        /// Removes one allowed nick for an owner and returns whether it existed.
        pub fn remove(self: *Self, owner: []const u8, nick: []const u8) DccAllowError!bool {
            try validateOwnerWith(params, owner);
            var nick_buf: [params.max_nick_bytes]u8 = undefined;
            const nick_key = try normalizeNickWith(params, nick, &nick_buf);
            var state = self.owners.getPtr(owner) orelse return false;

            if (!state.removeByKey(self.allocator, nick_key)) return false;
            if (state.count == 0) self.removeOwner(owner);
            return true;
        }

        /// Copies current entries for an owner into the caller-provided buffer.
        pub fn list(self: *const Self, owner: []const u8, buf: []Entry) DccAllowError![]Entry {
            try validateOwnerWith(params, owner);
            const state = self.owners.getPtr(owner) orelse return buf[0..0];
            if (buf.len < state.count) return error.OutputTooSmall;

            var index: usize = 0;
            var it = state.entries.iterator();
            while (it.next()) |entry| {
                buf[index] = .{
                    .nick = entry.value_ptr.nick,
                    .expires_at = entry.value_ptr.expires_at,
                };
                index += 1;
            }
            return buf[0..index];
        }

        /// Returns true when a nick is allowed for an owner at the given time.
        pub fn isAllowed(self: *const Self, owner: []const u8, nick: []const u8, now: i64) bool {
            validateOwnerWith(params, owner) catch return false;
            var nick_buf: [params.max_nick_bytes]u8 = undefined;
            const nick_key = normalizeNickWith(params, nick, &nick_buf) catch return false;
            const state = self.owners.getPtr(owner) orelse return false;
            const entry = state.entries.get(nick_key) orelse return false;
            return !isExpired(entry.expires_at, now);
        }

        /// Drops every expired entry and removes owners left with no entries.
        pub fn pruneExpired(self: *Self, now: i64) void {
            var it = self.owners.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.pruneExpired(self.allocator, now);
            }
            self.removeEmptyOwners();
        }

        fn getOrCreateOwner(self: *Self, owner: []const u8) DccAllowError!*OwnerState {
            try validateOwnerWith(params, owner);
            if (self.owners.getPtr(owner)) |state| return state;
            if (self.owner_count >= params.max_owners) return error.DccAllowFull;

            const owned_owner = try self.allocator.dupe(u8, owner);
            errdefer self.allocator.free(owned_owner);

            try self.owners.putNoClobber(owned_owner, OwnerState.init(self.allocator));
            self.owner_count += 1;
            return self.owners.getPtr(owned_owner).?;
        }

        fn removeOwner(self: *Self, owner: []const u8) void {
            var removed = self.owners.fetchRemove(owner).?;
            self.allocator.free(removed.key);
            removed.value.deinit(self.allocator);
            self.owner_count -= 1;
        }

        fn removeEmptyOwners(self: *Self) void {
            while (true) {
                var empty_owner: ?[]const u8 = null;
                var it = self.owners.iterator();
                while (it.next()) |entry| {
                    if (entry.value_ptr.count == 0) {
                        empty_owner = entry.key_ptr.*;
                        break;
                    }
                }

                if (empty_owner) |owner| {
                    self.removeOwner(owner);
                } else {
                    break;
                }
            }
        }
    };
}

/// Default DCCALLOW list type using production-oriented bounds.
pub const DccAllowList = DccAllowListWith(.{});

/// Parses DCCALLOW arguments using the default parser bounds.
pub fn parse(args: []const []const u8) DccAllowError!ParsedCommand(.{}) {
    return parseBounded(.{}, args);
}

/// Parses DCCALLOW arguments using caller-supplied parser bounds.
pub fn parseBounded(comptime bounds: Params, args: []const []const u8) DccAllowError!ParsedCommand(bounds) {
    var parsed = ParsedCommand(bounds){};
    if (args.len == 0) {
        try parsed.append(.{ .action = .list });
        return parsed;
    }

    for (args) |arg| {
        try parseTokenList(bounds, arg, &parsed);
    }
    return parsed;
}

/// Validates an owner identifier against the provided bounds.
pub fn validateOwnerWith(comptime params: Params, owner: []const u8) DccAllowError!void {
    if (owner.len == 0) return error.InvalidOwner;
    if (owner.len > params.max_owner_bytes) return error.OwnerTooLong;
    for (owner) |byte| {
        if (byte == 0 or byte <= 0x20 or byte == 0x7f) return error.InvalidOwner;
    }
}

/// Validates a nick against the provided bounds.
pub fn validateNickWith(comptime params: Params, nick: []const u8) DccAllowError!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > params.max_nick_bytes) return error.NickTooLong;
    for (nick) |byte| {
        if (!validNickByte(byte)) return error.InvalidNick;
    }
}

fn parseTokenList(comptime bounds: Params, arg: []const u8, parsed: *ParsedCommand(bounds)) DccAllowError!void {
    var start: usize = 0;
    while (start <= arg.len) {
        const end = std.mem.indexOfScalarPos(u8, arg, start, ',') orelse arg.len;
        try parseOne(bounds, arg[start..end], parsed);
        if (end == arg.len) break;
        start = end + 1;
    }
}

fn parseOne(comptime bounds: Params, raw: []const u8, parsed: *ParsedCommand(bounds)) DccAllowError!void {
    if (raw.len == 0) return error.MissingParameter;
    if (std.ascii.eqlIgnoreCase(raw, "HELP") or std.mem.eql(u8, raw, "?")) {
        try parsed.append(.{ .action = .help });
        return;
    }
    if (std.ascii.eqlIgnoreCase(raw, "LIST") or std.mem.eql(u8, raw, "*")) {
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

fn validateExpiryWith(comptime params: Params, expires_at: ?i64) DccAllowError!void {
    const timestamp = expires_at orelse return;
    if (timestamp < params.min_expiry_timestamp) return error.InvalidExpiry;
    if (timestamp > params.max_expiry_timestamp) return error.InvalidExpiry;
}

fn normalizeNickWith(comptime params: Params, nick: []const u8, out: *[params.max_nick_bytes]u8) DccAllowError![]const u8 {
    try validateNickWith(params, nick);
    for (nick, 0..) |byte, index| {
        out[index] = std.ascii.toLower(byte);
    }
    return out[0..nick.len];
}

fn isExpired(expires_at: ?i64, now: i64) bool {
    const timestamp = expires_at orelse return false;
    return timestamp <= now;
}

fn validNickByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '[', ']', '\\', '`', '_', '^', '{', '|', '}', '-' => true,
        else => false,
    };
}

test "numeric codes format as documented three digit replies" {
    // Arrange.
    var buf: [3]u8 = undefined;

    // Act.
    const status = DccAllowNumeric.RPL_DCCSTATUS.format(&buf);

    // Assert.
    try std.testing.expectEqual(@as(u16, 617), DccAllowNumeric.RPL_DCCSTATUS.code());
    try std.testing.expectEqualStrings("617", status);
    try std.testing.expectEqual(@as(u16, 618), DccAllowNumeric.RPL_DCCLIST.code());
    try std.testing.expectEqual(@as(u16, 619), DccAllowNumeric.RPL_ENDOFDCCLIST.code());
    try std.testing.expectEqual(@as(u16, 620), DccAllowNumeric.RPL_DCCINFO.code());
}

test "add remove list and isAllowed maintain per owner entries" {
    // Arrange.
    var list = DccAllowList.init(std.testing.allocator);
    defer list.deinit();

    // Act.
    try list.add("owner-a", "Alice", null);
    try list.add("owner-a", "Bob", null);
    const removed_alice = try list.remove("owner-a", "aLiCe");
    var entries_buf: [2]Entry = undefined;
    const entries = try list.list("owner-a", &entries_buf);

    // Assert.
    try std.testing.expect(removed_alice);
    try std.testing.expect(!try list.remove("owner-a", "Alice"));
    try std.testing.expect(!list.isAllowed("owner-a", "Alice", 100));
    try std.testing.expect(list.isAllowed("owner-a", "bob", 100));
    try std.testing.expect(!list.isAllowed("owner-b", "Bob", 100));
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("Bob", entries[0].nick);
    try std.testing.expectEqual(@as(?i64, null), entries[0].expires_at);
}

test "expiry is honored before at and after timestamp" {
    // Arrange.
    var list = DccAllowList.init(std.testing.allocator);
    defer list.deinit();

    // Act.
    try list.add("owner-a", "Alice", 200);

    // Assert.
    try std.testing.expect(list.isAllowed("owner-a", "ALICE", 199));
    try std.testing.expect(!list.isAllowed("owner-a", "ALICE", 200));
    try std.testing.expect(!list.isAllowed("owner-a", "ALICE", 201));
}

test "pruneExpired drops only expired entries and empty owners" {
    // Arrange.
    var list = DccAllowList.init(std.testing.allocator);
    defer list.deinit();
    try list.add("owner-a", "Alice", 10);
    try list.add("owner-a", "Bob", 30);
    try list.add("owner-b", "Carol", null);

    // Act.
    list.pruneExpired(20);
    var owner_a_buf: [2]Entry = undefined;
    const owner_a = try list.list("owner-a", &owner_a_buf);
    var owner_b_buf: [1]Entry = undefined;
    const owner_b = try list.list("owner-b", &owner_b_buf);

    // Assert.
    try std.testing.expect(!list.isAllowed("owner-a", "Alice", 20));
    try std.testing.expect(list.isAllowed("owner-a", "Bob", 20));
    try std.testing.expect(list.isAllowed("owner-b", "Carol", 20));
    try std.testing.expectEqual(@as(usize, 1), owner_a.len);
    try std.testing.expectEqualStrings("Bob", owner_a[0].nick);
    try std.testing.expectEqual(@as(usize, 1), owner_b.len);
}

test "duplicate add refreshes expiry without creating another entry" {
    // Arrange.
    var list = DccAllowList.init(std.testing.allocator);
    defer list.deinit();

    // Act.
    try list.add("owner-a", "Alice", 50);
    try list.add("owner-a", "ALICE", null);
    var entries_buf: [2]Entry = undefined;
    const entries = try list.list("owner-a", &entries_buf);

    // Assert.
    try std.testing.expect(list.isAllowed("owner-a", "alice", 1000));
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("Alice", entries[0].nick);
    try std.testing.expectEqual(@as(?i64, null), entries[0].expires_at);
}

test "limits reject excess owners entries and invalid inputs" {
    // Arrange.
    const Small = DccAllowListWith(.{
        .max_owners = 1,
        .max_entries_per_owner = 1,
        .max_owner_bytes = 8,
        .max_nick_bytes = 5,
        .max_expiry_timestamp = 100,
    });
    var list = Small.init(std.testing.allocator);
    defer list.deinit();

    // Act and assert.
    try list.add("owner-a", "Alice", 100);
    try std.testing.expectError(error.DccAllowFull, list.add("owner-a", "Bob", null));
    try std.testing.expectError(error.DccAllowFull, list.add("owner-b", "Carol", null));
    try std.testing.expectError(error.OwnerTooLong, list.add("owner-too-long", "Dan", null));
    try std.testing.expectError(error.NickTooLong, list.add("owner-a", "Robert", null));
    try std.testing.expectError(error.InvalidNick, list.add("owner-a", "Bad!", null));
    try std.testing.expectError(error.InvalidExpiry, list.add("owner-a", "Carol", 101));
}

test "list reports output buffer too small" {
    // Arrange.
    var list = DccAllowList.init(std.testing.allocator);
    defer list.deinit();
    try list.add("owner-a", "Alice", null);
    try list.add("owner-a", "Bob", null);
    var entries_buf: [1]Entry = undefined;

    // Act and assert.
    try std.testing.expectError(error.OutputTooSmall, list.list("owner-a", &entries_buf));
}

test "parse accepts add remove list and help operations without allocation" {
    // Arrange.
    const args = [_][]const u8{ "+Alice,-Bob", "LIST", "HELP", "?" };

    // Act.
    const parsed = try parse(&args);
    const ops = parsed.slice();
    const empty = try parse(&.{});

    // Assert.
    try std.testing.expectEqual(@as(usize, 5), ops.len);
    try std.testing.expectEqual(Action.add, ops[0].action);
    try std.testing.expectEqualStrings("Alice", ops[0].nick);
    try std.testing.expectEqual(Action.remove, ops[1].action);
    try std.testing.expectEqualStrings("Bob", ops[1].nick);
    try std.testing.expectEqual(Action.list, ops[2].action);
    try std.testing.expectEqual(Action.help, ops[3].action);
    try std.testing.expectEqual(Action.help, ops[4].action);
    try std.testing.expectEqual(Action.list, empty.slice()[0].action);
}

test "parse rejects empty invalid and excessive operations" {
    // Arrange.
    const TinyParsed = ParsedCommand(.{ .max_ops = 1 });
    var parsed = TinyParsed{};

    // Act and assert.
    try parsed.append(.{ .action = .list });
    try std.testing.expectError(error.TooManyOperations, parsed.append(.{ .action = .help }));
    try std.testing.expectError(error.MissingParameter, parse(&.{""}));
    try std.testing.expectError(error.MissingParameter, parse(&.{"Alice"}));
    try std.testing.expectError(error.InvalidNick, parse(&.{"+"}));
    try std.testing.expectError(error.InvalidNick, parse(&.{"+bad nick"}));
    try std.testing.expectError(error.TooManyOperations, parseBounded(.{ .max_ops = 1 }, &.{ "+Alice", "-Bob" }));
}
