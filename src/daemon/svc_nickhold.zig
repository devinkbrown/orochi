//! Pure nickname hold/forbid policy for Mizuchi services.
//!
//! This module owns no IRC I/O and imports no daemon/protocol code. It models
//! the service data and command parsing for real server-side commands that can
//! reserve or forbid nickname glob patterns before registration or nick changes.

const std = @import("std");

pub const Limits = struct {
    max_entries: usize = 256,
    max_pattern_len: usize = 64,
    max_reason_len: usize = 160,
    max_setter_len: usize = 64,
};

pub const default_limits = Limits{};

pub const Mode = enum {
    reserve,
    forbid,

    pub fn token(self: Mode) []const u8 {
        return switch (self) {
            .reserve => "RESERVE",
            .forbid => "FORBID",
        };
    }

    pub fn parse(bytes: []const u8) ?Mode {
        if (std.ascii.eqlIgnoreCase(bytes, "RESERVE")) return .reserve;
        if (std.ascii.eqlIgnoreCase(bytes, "RESERVED")) return .reserve;
        if (std.ascii.eqlIgnoreCase(bytes, "HOLD")) return .reserve;
        if (std.ascii.eqlIgnoreCase(bytes, "FORBID")) return .forbid;
        if (std.ascii.eqlIgnoreCase(bytes, "FORBIDDEN")) return .forbid;
        if (std.ascii.eqlIgnoreCase(bytes, "Q")) return .forbid;
        return null;
    }
};

pub const AddRequest = struct {
    mode: Mode,
    pattern: []const u8,
    setter: []const u8,
    reason: []const u8,
};

pub const ParsedCommand = union(enum) {
    add: AddRequest,
    remove: []const u8,
    list,
    check: []const u8,
};

pub const ParseError = error{
    MissingCommand,
    UnknownCommand,
    MissingParam,
    InvalidMode,
    EmptyReason,
    TrailingParam,
};

pub const HoldError = error{
    EmptyPattern,
    PatternTooLong,
    InvalidPattern,
    EmptySetter,
    SetterTooLong,
    EmptyReason,
    ReasonTooLong,
    TooManyEntries,
};

pub const AddResult = enum {
    inserted,
    replaced,
};

pub const CommandResult = union(enum) {
    added: AddResult,
    removed: bool,
    listed: usize,
    tested: bool,
};

pub const NickHold = Registry(default_limits);

pub fn Registry(comptime limits: Limits) type {
    comptime {
        if (limits.max_pattern_len == 0) @compileError("max_pattern_len must be non-zero");
        if (limits.max_setter_len == 0) @compileError("max_setter_len must be non-zero");
        if (limits.max_reason_len == 0) @compileError("max_reason_len must be non-zero");
    }

    const Pattern = InlineText(limits.max_pattern_len);
    const Setter = InlineText(limits.max_setter_len);
    const Reason = InlineText(limits.max_reason_len);

    return struct {
        const Self = @This();

        pub const Entry = struct {
            mode: Mode,
            pattern: Pattern,
            setter: Setter,
            reason: Reason,

            pub fn patternSlice(self: *const Entry) []const u8 {
                return self.pattern.slice();
            }

            pub fn setterSlice(self: *const Entry) []const u8 {
                return self.setter.slice();
            }

            pub fn reasonSlice(self: *const Entry) []const u8 {
                return self.reason.slice();
            }
        };

        entries: [limits.max_entries]Entry = undefined,
        len: usize = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        pub fn add(self: *Self, req: AddRequest) HoldError!AddResult {
            try validateAdd(req);

            const entry = Entry{
                .mode = req.mode,
                .pattern = Pattern.init(req.pattern) catch unreachable,
                .setter = Setter.init(req.setter) catch unreachable,
                .reason = Reason.init(req.reason) catch unreachable,
            };

            if (self.indexOf(req.pattern)) |idx| {
                self.entries[idx] = entry;
                return .replaced;
            }

            if (self.len >= limits.max_entries) return error.TooManyEntries;
            self.entries[self.len] = entry;
            self.len += 1;
            return .inserted;
        }

        pub fn remove(self: *Self, pattern: []const u8) bool {
            const idx = self.indexOf(pattern) orelse return false;
            var i = idx;
            while (i + 1 < self.len) : (i += 1) {
                self.entries[i] = self.entries[i + 1];
            }
            self.len -= 1;
            return true;
        }

        pub fn isReserved(self: *const Self, nick: []const u8) bool {
            return self.match(nick) != null;
        }

        pub fn match(self: *const Self, nick: []const u8) ?Entry {
            if (nick.len == 0) return null;
            for (self.entries[0..self.len]) |entry| {
                if (globMatch(entry.pattern.slice(), nick)) return entry;
            }
            return null;
        }

        pub fn list(self: *const Self, out: []Entry) []const Entry {
            const n = @min(out.len, self.len);
            if (n != 0) @memcpy(out[0..n], self.entries[0..n]);
            return out[0..n];
        }

        pub fn apply(self: *Self, command: ParsedCommand) HoldError!CommandResult {
            return switch (command) {
                .add => |req| .{ .added = try self.add(req) },
                .remove => |pattern| .{ .removed = self.remove(pattern) },
                .list => .{ .listed = self.count() },
                .check => |nick| .{ .tested = self.isReserved(nick) },
            };
        }

        fn indexOf(self: *const Self, pattern: []const u8) ?usize {
            for (self.entries[0..self.len], 0..) |entry, idx| {
                if (patternEql(entry.pattern.slice(), pattern)) return idx;
            }
            return null;
        }

        fn validateAdd(req: AddRequest) HoldError!void {
            if (req.pattern.len == 0) return error.EmptyPattern;
            if (req.pattern.len > limits.max_pattern_len) return error.PatternTooLong;
            if (!validNickPattern(req.pattern)) return error.InvalidPattern;
            if (req.setter.len == 0) return error.EmptySetter;
            if (req.setter.len > limits.max_setter_len) return error.SetterTooLong;
            if (req.reason.len == 0) return error.EmptyReason;
            if (req.reason.len > limits.max_reason_len) return error.ReasonTooLong;
        }
    };
}

pub fn parseCommand(input: []const u8) ParseError!ParsedCommand {
    var cursor = Cursor.init(trimLine(input));
    var first = cursor.next() orelse return error.MissingCommand;
    if (first.trailing) return error.UnknownCommand;

    if (std.ascii.eqlIgnoreCase(first.bytes, "NICKHOLD")) {
        first = cursor.next() orelse return error.MissingCommand;
        if (first.trailing) return error.UnknownCommand;
    }

    if (std.ascii.eqlIgnoreCase(first.bytes, "ADD")) {
        const mode_token = cursor.next() orelse return error.MissingParam;
        if (mode_token.trailing) return error.InvalidMode;
        const mode = Mode.parse(mode_token.bytes) orelse return error.InvalidMode;
        return .{ .add = try parseAddRest(&cursor, mode) };
    }

    if (Mode.parse(first.bytes)) |mode| {
        return .{ .add = try parseAddRest(&cursor, mode) };
    }

    if (std.ascii.eqlIgnoreCase(first.bytes, "REMOVE") or
        std.ascii.eqlIgnoreCase(first.bytes, "DEL") or
        std.ascii.eqlIgnoreCase(first.bytes, "DELETE"))
    {
        const pattern = cursor.next() orelse return error.MissingParam;
        if (pattern.trailing) return error.MissingParam;
        try expectEnd(&cursor);
        return .{ .remove = pattern.bytes };
    }

    if (std.ascii.eqlIgnoreCase(first.bytes, "LIST")) {
        try expectEnd(&cursor);
        return .list;
    }

    if (std.ascii.eqlIgnoreCase(first.bytes, "TEST") or
        std.ascii.eqlIgnoreCase(first.bytes, "CHECK"))
    {
        const nick = cursor.next() orelse return error.MissingParam;
        if (nick.trailing) return error.MissingParam;
        try expectEnd(&cursor);
        return .{ .check = nick.bytes };
    }

    return error.UnknownCommand;
}

fn parseAddRest(cursor: *Cursor, mode: Mode) ParseError!AddRequest {
    const pattern = cursor.next() orelse return error.MissingParam;
    if (pattern.trailing) return error.MissingParam;
    const setter = cursor.next() orelse return error.MissingParam;
    if (setter.trailing) return error.MissingParam;
    const reason = cursor.next() orelse return error.MissingParam;
    if (reason.bytes.len == 0) return error.EmptyReason;
    if (!reason.trailing) try expectEnd(cursor);
    return .{
        .mode = mode,
        .pattern = pattern.bytes,
        .setter = setter.bytes,
        .reason = reason.bytes,
    };
}

fn expectEnd(cursor: *Cursor) ParseError!void {
    if (cursor.next() != null) return error.TrailingParam;
}

fn InlineText(comptime max_len: usize) type {
    return struct {
        bytes: [max_len]u8 = [_]u8{0} ** max_len,
        len: usize = 0,

        fn init(input: []const u8) error{StringTooLong}!@This() {
            if (input.len > max_len) return error.StringTooLong;
            var out = @This(){};
            if (input.len != 0) @memcpy(out.bytes[0..input.len], input);
            out.len = input.len;
            return out;
        }

        pub fn slice(self: *const @This()) []const u8 {
            return self.bytes[0..self.len];
        }
    };
}

const Token = struct {
    bytes: []const u8,
    trailing: bool = false,
};

const Cursor = struct {
    input: []const u8,
    index: usize = 0,

    fn init(input: []const u8) Cursor {
        return .{ .input = input };
    }

    fn next(self: *Cursor) ?Token {
        while (self.index < self.input.len and self.input[self.index] == ' ') {
            self.index += 1;
        }
        if (self.index >= self.input.len) return null;

        if (self.input[self.index] == ':') {
            const bytes = self.input[self.index + 1 ..];
            self.index = self.input.len;
            return .{ .bytes = bytes, .trailing = true };
        }

        const start = self.index;
        while (self.index < self.input.len and self.input[self.index] != ' ') {
            self.index += 1;
        }
        return .{ .bytes = self.input[start..self.index] };
    }
};

fn trimLine(input: []const u8) []const u8 {
    return std.mem.trim(u8, input, " \t\r\n");
}

pub fn globMatch(pattern: []const u8, text: []const u8) bool {
    var pattern_index: usize = 0;
    var text_index: usize = 0;
    var star_index: ?usize = null;
    var star_text_index: usize = 0;

    while (text_index < text.len) {
        if (pattern_index < pattern.len) {
            const token = nextGlobToken(pattern, pattern_index);
            switch (token.kind) {
                .any_run => {
                    star_index = pattern_index;
                    pattern_index = token.next;
                    star_text_index = text_index;
                    continue;
                },
                .any_one => {
                    pattern_index = token.next;
                    text_index += 1;
                    continue;
                },
                .literal => {
                    if (rfc1459Fold(token.byte) == rfc1459Fold(text[text_index])) {
                        pattern_index = token.next;
                        text_index += 1;
                        continue;
                    }
                },
            }
        }

        if (star_index) |idx| {
            const token = nextGlobToken(pattern, idx);
            star_text_index += 1;
            text_index = star_text_index;
            pattern_index = token.next;
        } else {
            return false;
        }
    }

    while (pattern_index < pattern.len) {
        const token = nextGlobToken(pattern, pattern_index);
        if (token.kind != .any_run) return false;
        pattern_index = token.next;
    }
    return true;
}

const GlobTokenKind = enum {
    literal,
    any_one,
    any_run,
};

const GlobToken = struct {
    kind: GlobTokenKind,
    byte: u8 = 0,
    next: usize,
};

fn nextGlobToken(pattern: []const u8, index: usize) GlobToken {
    const byte = pattern[index];
    if (byte == '\\' and index + 1 < pattern.len and isEscapable(pattern[index + 1])) {
        return .{ .kind = .literal, .byte = pattern[index + 1], .next = index + 2 };
    }
    return switch (byte) {
        '*' => .{ .kind = .any_run, .next = index + 1 },
        '?' => .{ .kind = .any_one, .next = index + 1 },
        else => .{ .kind = .literal, .byte = byte, .next = index + 1 },
    };
}

fn isEscapable(byte: u8) bool {
    return byte == '*' or byte == '?' or byte == '\\';
}

fn rfc1459Fold(byte: u8) u8 {
    return switch (byte) {
        'A'...'Z' => byte + ('a' - 'A'),
        '[' => '{',
        ']' => '}',
        '\\' => '|',
        '^' => '~',
        else => byte,
    };
}

fn patternEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (rfc1459Fold(left) != rfc1459Fold(right)) return false;
    }
    return true;
}

fn validNickPattern(pattern: []const u8) bool {
    for (pattern) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return false;
        if (byte == '!' or byte == '@' or byte == '#' or byte == ':' or byte == ',') return false;
    }
    return true;
}

const testing = std.testing;

test "add list match remove with reason and setter metadata" {
    var holds = NickHold.init();

    const inserted = try holds.add(.{
        .mode = .reserve,
        .pattern = "Staff*",
        .setter = "oper1",
        .reason = "staff namespace",
    });
    try testing.expectEqual(AddResult.inserted, inserted);
    try testing.expect(holds.isReserved("staff42"));
    try testing.expect(!holds.isReserved("guest42"));

    const hit = holds.match("STAFF").?;
    try testing.expectEqual(Mode.reserve, hit.mode);
    try testing.expectEqualStrings("Staff*", hit.patternSlice());
    try testing.expectEqualStrings("oper1", hit.setterSlice());
    try testing.expectEqualStrings("staff namespace", hit.reasonSlice());

    var out: [4]NickHold.Entry = undefined;
    const listed = holds.list(&out);
    try testing.expectEqual(@as(usize, 1), listed.len);
    try testing.expectEqualStrings("Staff*", listed[0].patternSlice());

    try testing.expect(holds.remove("staff*"));
    try testing.expect(!holds.isReserved("staff42"));
    try testing.expect(!holds.remove("staff*"));
}

test "forbid patterns and reserve patterns both block use" {
    var holds = NickHold.init();

    try testing.expectEqual(AddResult.inserted, try holds.add(.{
        .mode = .forbid,
        .pattern = "Admin",
        .setter = "oper",
        .reason = "reserved server role",
    }));
    try testing.expectEqual(AddResult.inserted, try holds.add(.{
        .mode = .reserve,
        .pattern = "Project-*",
        .setter = "services",
        .reason = "project aliases",
    }));

    try testing.expect(holds.isReserved("admin"));
    try testing.expect(holds.isReserved("PROJECT-alpha"));
    try testing.expect(!holds.isReserved("ordinary"));
    try testing.expectEqual(Mode.forbid, holds.match("ADMIN").?.mode);
    try testing.expectEqual(Mode.reserve, holds.match("project-beta").?.mode);
}

test "adding the same pattern replaces metadata without growing" {
    var holds = NickHold.init();

    try testing.expectEqual(AddResult.inserted, try holds.add(.{
        .mode = .reserve,
        .pattern = "Guest*",
        .setter = "one",
        .reason = "first",
    }));
    try testing.expectEqual(AddResult.replaced, try holds.add(.{
        .mode = .forbid,
        .pattern = "guest*",
        .setter = "two",
        .reason = "second",
    }));

    try testing.expectEqual(@as(usize, 1), holds.count());
    const hit = holds.match("GUEST123").?;
    try testing.expectEqual(Mode.forbid, hit.mode);
    try testing.expectEqualStrings("two", hit.setterSlice());
    try testing.expectEqualStrings("second", hit.reasonSlice());
}

test "fixed limits reject invalid entries and permit replacement at capacity" {
    const Small = Registry(.{
        .max_entries = 1,
        .max_pattern_len = 8,
        .max_reason_len = 6,
        .max_setter_len = 5,
    });
    var holds = Small.init();

    try testing.expectError(error.EmptyPattern, holds.add(.{
        .mode = .reserve,
        .pattern = "",
        .setter = "oper",
        .reason = "ok",
    }));
    try testing.expectError(error.PatternTooLong, holds.add(.{
        .mode = .reserve,
        .pattern = "TooLongPattern",
        .setter = "oper",
        .reason = "ok",
    }));
    try testing.expectError(error.InvalidPattern, holds.add(.{
        .mode = .reserve,
        .pattern = "bad!x",
        .setter = "oper",
        .reason = "ok",
    }));
    try testing.expectError(error.EmptySetter, holds.add(.{
        .mode = .reserve,
        .pattern = "Nick",
        .setter = "",
        .reason = "ok",
    }));
    try testing.expectError(error.SetterTooLong, holds.add(.{
        .mode = .reserve,
        .pattern = "Nick",
        .setter = "longer",
        .reason = "ok",
    }));
    try testing.expectError(error.EmptyReason, holds.add(.{
        .mode = .reserve,
        .pattern = "Nick",
        .setter = "oper",
        .reason = "",
    }));
    try testing.expectError(error.ReasonTooLong, holds.add(.{
        .mode = .reserve,
        .pattern = "Nick",
        .setter = "oper",
        .reason = "toolong",
    }));

    _ = try holds.add(.{ .mode = .reserve, .pattern = "One", .setter = "oper", .reason = "one" });
    try testing.expectEqual(AddResult.replaced, try holds.add(.{
        .mode = .forbid,
        .pattern = "one",
        .setter = "oper",
        .reason = "two",
    }));
    try testing.expectError(error.TooManyEntries, holds.add(.{
        .mode = .reserve,
        .pattern = "Two",
        .setter = "oper",
        .reason = "two",
    }));
}

test "list truncates to caller buffer without mutating storage" {
    var holds = NickHold.init();
    _ = try holds.add(.{ .mode = .reserve, .pattern = "One", .setter = "oper", .reason = "r1" });
    _ = try holds.add(.{ .mode = .forbid, .pattern = "Two", .setter = "oper", .reason = "r2" });

    var out: [1]NickHold.Entry = undefined;
    const listed = holds.list(&out);

    try testing.expectEqual(@as(usize, 1), listed.len);
    try testing.expectEqual(@as(usize, 2), holds.count());
    try testing.expectEqualStrings("One", listed[0].patternSlice());
}

test "glob matching is anchored case-insensitive and supports escaped wildcards" {
    try testing.expect(globMatch("*", ""));
    try testing.expect(globMatch("n?ck*", "NickName"));
    try testing.expect(globMatch("[\\]^", "{|}~"));
    try testing.expect(globMatch("literal\\*", "literal*"));
    try testing.expect(globMatch("what\\?", "what?"));
    try testing.expect(!globMatch("literal\\*", "literal123"));
    try testing.expect(!globMatch("admin", "xadmin"));
    try testing.expect(!globMatch("admin", "adminx"));
}

test "parser accepts full NICKHOLD add remove list and test commands" {
    const add = try parseCommand("NICKHOLD ADD RESERVE Staff* oper :staff namespace");
    switch (add) {
        .add => |req| {
            try testing.expectEqual(Mode.reserve, req.mode);
            try testing.expectEqualStrings("Staff*", req.pattern);
            try testing.expectEqualStrings("oper", req.setter);
            try testing.expectEqualStrings("staff namespace", req.reason);
        },
        else => return error.TestUnexpectedResult,
    }

    const rem = try parseCommand("NICKHOLD DEL Staff*");
    switch (rem) {
        .remove => |pattern| try testing.expectEqualStrings("Staff*", pattern),
        else => return error.TestUnexpectedResult,
    }

    try testing.expectEqual(ParsedCommand.list, try parseCommand("NICKHOLD LIST"));

    const check = try parseCommand("NICKHOLD CHECK Staff42");
    switch (check) {
        .check => |nick| try testing.expectEqualStrings("Staff42", nick),
        else => return error.TestUnexpectedResult,
    }
}

test "parser accepts shorthand reserve and forbid command forms" {
    const reserve = try parseCommand("RESERVE Root services :root nick");
    switch (reserve) {
        .add => |req| {
            try testing.expectEqual(Mode.reserve, req.mode);
            try testing.expectEqualStrings("Root", req.pattern);
        },
        else => return error.TestUnexpectedResult,
    }

    const forbid = try parseCommand("NICKHOLD FORBID Oper* admin :oper namespace");
    switch (forbid) {
        .add => |req| {
            try testing.expectEqual(Mode.forbid, req.mode);
            try testing.expectEqualStrings("Oper*", req.pattern);
            try testing.expectEqualStrings("oper namespace", req.reason);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parser rejects malformed command lines" {
    try testing.expectError(error.MissingCommand, parseCommand(""));
    try testing.expectError(error.UnknownCommand, parseCommand("NICKHOLD BOGUS"));
    try testing.expectError(error.InvalidMode, parseCommand("NICKHOLD ADD BAD Nick oper :reason"));
    try testing.expectError(error.MissingParam, parseCommand("NICKHOLD ADD RESERVE Nick oper"));
    try testing.expectError(error.EmptyReason, parseCommand("NICKHOLD ADD RESERVE Nick oper :"));
    try testing.expectError(error.TrailingParam, parseCommand("NICKHOLD LIST extra"));
    try testing.expectError(error.TrailingParam, parseCommand("NICKHOLD TEST Nick extra"));
}

test "apply command wires parser to registry logic" {
    var holds = NickHold.init();

    const add = try parseCommand("NICKHOLD FORBID Root* oper :server namespace");
    try testing.expectEqual(AddResult.inserted, (try holds.apply(add)).added);
    try testing.expect((try holds.apply(try parseCommand("NICKHOLD TEST root42"))).tested);
    try testing.expectEqual(@as(usize, 1), (try holds.apply(try parseCommand("NICKHOLD LIST"))).listed);
    try testing.expect((try holds.apply(try parseCommand("NICKHOLD REMOVE ROOT*"))).removed);
    try testing.expect(!(try holds.apply(try parseCommand("NICKHOLD TEST root42"))).tested);
}

test "bounded churn across insert replace remove has no allocation path" {
    const Small = Registry(.{
        .max_entries = 16,
        .max_pattern_len = 16,
        .max_reason_len = 16,
        .max_setter_len = 8,
    });
    var holds = Small.init();

    for (0..16) |idx| {
        var pattern_buf: [16]u8 = undefined;
        const pattern = try std.fmt.bufPrint(&pattern_buf, "n{d}*", .{idx});
        _ = try holds.add(.{ .mode = .reserve, .pattern = pattern, .setter = "oper", .reason = "batch" });
    }
    try testing.expectEqual(@as(usize, 16), holds.count());

    for (0..16) |idx| {
        var pattern_buf: [16]u8 = undefined;
        const pattern = try std.fmt.bufPrint(&pattern_buf, "N{d}*", .{idx});
        try testing.expectEqual(AddResult.replaced, try holds.add(.{
            .mode = .forbid,
            .pattern = pattern,
            .setter = "oper",
            .reason = "swap",
        }));
    }

    for (0..16) |idx| {
        var pattern_buf: [16]u8 = undefined;
        const pattern = try std.fmt.bufPrint(&pattern_buf, "n{d}*", .{idx});
        try testing.expect(holds.remove(pattern));
    }
    try testing.expectEqual(@as(usize, 0), holds.count());
}
