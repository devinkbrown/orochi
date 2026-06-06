const std = @import("std");

pub const CommandEntry = struct {
    command: []const u8,
    count: u64,
    last_used: u64,
};

pub const CommandStats = struct {
    pub const Config = struct {
        max_commands: usize = 2048,
        max_command_bytes: usize = 48,
    };

    pub const Error = std.mem.Allocator.Error || error{ EmptyCommand, CommandTooLong, InvalidCommand, TooManyCommands };

    const State = struct {
        count: u64,
        last_used: u64,
    };

    allocator: std.mem.Allocator,
    cfg: Config,
    commands: std.StringHashMap(State),

    pub fn init(allocator: std.mem.Allocator) CommandStats {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) CommandStats {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .commands = std.StringHashMap(State).init(allocator),
        };
    }

    pub fn deinit(self: *CommandStats) void {
        var it = self.commands.iterator();
        while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.commands.deinit();
        self.* = undefined;
    }

    pub fn bump(self: *CommandStats, cmd: []const u8, now: u64) Error!void {
        var buf: [256]u8 = undefined;
        const normalized = try normalizeCommand(&buf, cmd, self.cfg.max_command_bytes);
        const entry = try self.ensureCommand(normalized);
        entry.value_ptr.count +%= 1;
        entry.value_ptr.last_used = now;
    }

    pub fn count(self: *const CommandStats, cmd: []const u8) u64 {
        var buf: [256]u8 = undefined;
        const normalized = normalizeCommand(&buf, cmd, self.cfg.max_command_bytes) catch return 0;
        const state = self.commands.get(normalized) orelse return 0;
        return state.count;
    }

    pub fn top(self: *const CommandStats, n: usize, out: []CommandEntry) usize {
        const limit = @min(n, out.len);
        if (limit == 0) return 0;

        var used: usize = 0;
        var it = self.commands.iterator();
        while (it.next()) |entry| {
            insertTop(out[0..limit], &used, .{
                .command = entry.key_ptr.*,
                .count = entry.value_ptr.count,
                .last_used = entry.value_ptr.last_used,
            });
        }
        return used;
    }

    fn ensureCommand(self: *CommandStats, command: []const u8) Error!std.StringHashMap(State).Entry {
        if (self.commands.getEntry(command)) |entry| return entry;
        if (self.commands.count() >= self.cfg.max_commands) return error.TooManyCommands;

        const owned = try self.allocator.dupe(u8, command);
        errdefer self.allocator.free(owned);
        try self.commands.putNoClobber(owned, .{ .count = 0, .last_used = 0 });
        return self.commands.getEntry(owned).?;
    }

    fn normalizeCommand(buf: []u8, cmd: []const u8, max_command_bytes: usize) Error![]const u8 {
        const raw = if (cmd.len > 0 and cmd[0] == '!') cmd[1..] else cmd;
        if (raw.len == 0) return error.EmptyCommand;
        if (raw.len > max_command_bytes or raw.len > buf.len) return error.CommandTooLong;

        for (raw, 0..) |byte, i| {
            if (!(std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '-')) return error.InvalidCommand;
            buf[i] = std.ascii.toLower(byte);
        }
        return buf[0..raw.len];
    }

    fn insertTop(out: []CommandEntry, used: *usize, item: CommandEntry) void {
        var pos: usize = 0;
        while (pos < used.* and better(out[pos], item)) pos += 1;
        if (pos >= out.len) return;

        if (used.* < out.len) used.* += 1;
        var i = used.* - 1;
        while (i > pos) : (i -= 1) out[i] = out[i - 1];
        out[pos] = item;
    }

    fn better(a: CommandEntry, b: CommandEntry) bool {
        if (a.count != b.count) return a.count > b.count;
        if (a.last_used != b.last_used) return a.last_used > b.last_used;
        return std.mem.lessThan(u8, a.command, b.command);
    }
};

const testing = std.testing;

test "bump counts commands case-insensitively" {
    var stats = CommandStats.init(testing.allocator);
    defer stats.deinit();

    try stats.bump("!Help", 10);
    try stats.bump("help", 12);
    try stats.bump("!stats", 20);

    try testing.expectEqual(@as(u64, 2), stats.count("!HELP"));
    try testing.expectEqual(@as(u64, 1), stats.count("stats"));
    try testing.expectEqual(@as(u64, 0), stats.count("missing"));
}

test "top ranks by count then last-used" {
    var stats = CommandStats.init(testing.allocator);
    defer stats.deinit();

    try stats.bump("one", 1);
    try stats.bump("two", 2);
    try stats.bump("two", 3);
    try stats.bump("three", 9);

    var out: [3]CommandEntry = undefined;
    const n = stats.top(3, &out);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualStrings("two", out[0].command);
    try testing.expectEqual(@as(u64, 2), out[0].count);
    try testing.expectEqualStrings("three", out[1].command);
}

test "top respects output and requested limits" {
    var stats = CommandStats.init(testing.allocator);
    defer stats.deinit();

    try stats.bump("a", 1);
    try stats.bump("b", 2);
    try stats.bump("c", 3);

    var out: [1]CommandEntry = undefined;
    const n = stats.top(2, &out);
    try testing.expectEqual(@as(usize, 1), n);
}

test "invalid commands and configured bounds are enforced" {
    var stats = CommandStats.initWithConfig(testing.allocator, .{
        .max_commands = 1,
        .max_command_bytes = 8,
    });
    defer stats.deinit();

    try testing.expectError(error.EmptyCommand, stats.bump("!", 0));
    try testing.expectError(error.InvalidCommand, stats.bump("bad.cmd", 0));
    try testing.expectError(error.CommandTooLong, stats.bump("verylarge", 0));
    try stats.bump("ok", 1);
    try testing.expectError(error.TooManyCommands, stats.bump("next", 2));
}
