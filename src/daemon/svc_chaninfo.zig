//! Pure registered-channel INFO rendering.
//!
//! Services are represented as real server commands and real numerics. This
//! module deliberately has no daemon/protocol imports and never formats
//! pseudo-client service notices.

const std = @import("std");

pub const max_channel_bytes = 128;
pub const max_account_bytes = 64;
pub const max_server_bytes = 255;
pub const max_requester_bytes = 64;
pub const max_flag_bytes = 32;
pub const max_setting_key_bytes = 48;
pub const max_setting_value_bytes = 512;
pub const max_description_bytes = 512;
pub const max_record_line_bytes = 1024;

pub const ChannelInfoNumeric = enum(u16) {
    RPL_INFO = 371,
    RPL_INFOSTART = 373,
    RPL_ENDOFINFO = 374,

    pub fn code(self: ChannelInfoNumeric) u16 {
        return @intFromEnum(self);
    }

    pub fn tag(self: ChannelInfoNumeric) []const u8 {
        return switch (self) {
            .RPL_INFO => "RPL_INFO",
            .RPL_INFOSTART => "RPL_INFOSTART",
            .RPL_ENDOFINFO => "RPL_ENDOFINFO",
        };
    }

    pub fn format(self: ChannelInfoNumeric) []const u8 {
        return switch (self) {
            .RPL_INFO => "371",
            .RPL_INFOSTART => "373",
            .RPL_ENDOFINFO => "374",
        };
    }
};

pub const ChannelInfoError = std.mem.Allocator.Error || error{
    EmptyServerName,
    ServerNameTooLong,
    InvalidServerName,
    EmptyRequester,
    RequesterTooLong,
    InvalidRequester,
    EmptyChannel,
    ChannelTooLong,
    InvalidChannel,
    EmptyFounder,
    FounderTooLong,
    InvalidFounder,
    InvalidTimestamp,
    DescriptionTooLong,
    InvalidDescription,
    EmptyFlag,
    FlagTooLong,
    InvalidFlag,
    EmptySettingKey,
    SettingKeyTooLong,
    InvalidSettingKey,
    SettingValueTooLong,
    InvalidSettingValue,
    SuccessorTooLong,
    InvalidSuccessor,
    OutputTooSmall,
};

pub const ParseError = ChannelInfoError || error{
    EmptyInput,
    InvalidRecordLine,
    UnknownField,
    DuplicateField,
    MissingChannel,
    MissingFounder,
    MissingRegisteredAt,
    InvalidInteger,
};

pub const RenderContext = struct {
    server_name: []const u8,
    requester: []const u8,
    include_crlf: bool = true,
};

pub const Setting = struct {
    key: []const u8,
    value: []const u8,
};

pub const ChannelRecord = struct {
    channel: []const u8,
    founder: []const u8,
    registered_at: i64,
    last_used_at: ?i64 = null,
    description: ?[]const u8 = null,
    flags: []const []const u8 = &.{},
    settings: []const Setting = &.{},
    successor: ?[]const u8 = null,

    pub fn validate(self: ChannelRecord) ChannelInfoError!void {
        try validateChannel(self.channel);
        try validateAccount(self.founder, error.EmptyFounder, error.FounderTooLong, error.InvalidFounder);
        try validateTimestamp(self.registered_at);
        if (self.last_used_at) |last_used_at| try validateTimestamp(last_used_at);
        if (self.description) |description| try validateDescription(description);
        for (self.flags) |flag| try validateFlag(flag);
        for (self.settings) |setting| {
            try validateSettingKey(setting.key);
            try validateSettingValue(setting.value);
        }
        if (self.successor) |successor| try validateSuccessor(successor);
    }

    pub fn hasFlag(self: ChannelRecord, flag: []const u8) bool {
        for (self.flags) |candidate| {
            if (std.ascii.eqlIgnoreCase(candidate, flag)) return true;
        }
        return false;
    }

    pub fn settingValue(self: ChannelRecord, key: []const u8) ?[]const u8 {
        for (self.settings) |setting| {
            if (std.ascii.eqlIgnoreCase(setting.key, key)) return setting.value;
        }
        return null;
    }
};

pub const RenderedInfo = struct {
    lines: []const []u8,

    pub fn deinit(self: *RenderedInfo, allocator: std.mem.Allocator) void {
        for (self.lines) |line| allocator.free(line);
        allocator.free(self.lines);
        self.* = .{ .lines = &.{} };
    }
};

pub const OwnedChannelRecord = struct {
    channel: []u8,
    founder: []u8,
    registered_at: i64,
    last_used_at: ?i64 = null,
    description: ?[]u8 = null,
    flags: []const []u8 = &.{},
    settings: []const OwnedSetting = &.{},
    successor: ?[]u8 = null,

    pub const OwnedSetting = struct {
        key: []u8,
        value: []u8,
    };

    pub fn asRecord(self: *const OwnedChannelRecord) ChannelRecord {
        return .{
            .channel = self.channel,
            .founder = self.founder,
            .registered_at = self.registered_at,
            .last_used_at = self.last_used_at,
            .description = self.description,
            .flags = self.flags,
            .settings = ownedSettingsAsBorrowed(self.settings),
            .successor = self.successor,
        };
    }

    pub fn deinit(self: *OwnedChannelRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.channel);
        allocator.free(self.founder);
        if (self.description) |description| allocator.free(description);
        for (self.flags) |flag| allocator.free(flag);
        allocator.free(self.flags);
        for (self.settings) |setting| {
            allocator.free(setting.key);
            allocator.free(setting.value);
        }
        allocator.free(self.settings);
        if (self.successor) |successor| allocator.free(successor);
        self.* = undefined;
    }
};

pub fn parseRecord(allocator: std.mem.Allocator, text: []const u8) ParseError!OwnedChannelRecord {
    if (text.len == 0) return error.EmptyInput;

    var channel: ?[]u8 = null;
    errdefer if (channel) |value| allocator.free(value);

    var founder: ?[]u8 = null;
    errdefer if (founder) |value| allocator.free(value);

    var registered_at: ?i64 = null;
    var last_used_at: ?i64 = null;

    var description: ?[]u8 = null;
    errdefer if (description) |value| allocator.free(value);

    var flags: std.ArrayListUnmanaged([]u8) = .empty;
    defer flags.deinit(allocator);
    errdefer for (flags.items) |flag| allocator.free(flag);

    var settings: std.ArrayListUnmanaged(OwnedChannelRecord.OwnedSetting) = .empty;
    defer settings.deinit(allocator);
    errdefer for (settings.items) |setting| {
        allocator.free(setting.key);
        allocator.free(setting.value);
    };

    var successor: ?[]u8 = null;
    errdefer if (successor) |value| allocator.free(value);

    var saw_line = false;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, "\r");
        if (line.len == 0) continue;
        saw_line = true;
        if (line.len > max_record_line_bytes) return error.InvalidRecordLine;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse return error.InvalidRecordLine;
        const field = line[0..eq];
        const value = line[eq + 1 ..];
        if (field.len == 0) return error.InvalidRecordLine;

        if (std.ascii.eqlIgnoreCase(field, "channel")) {
            if (channel != null) return error.DuplicateField;
            try validateChannel(value);
            channel = try allocator.dupe(u8, value);
        } else if (std.ascii.eqlIgnoreCase(field, "founder")) {
            if (founder != null) return error.DuplicateField;
            try validateAccount(value, error.EmptyFounder, error.FounderTooLong, error.InvalidFounder);
            founder = try allocator.dupe(u8, value);
        } else if (std.ascii.eqlIgnoreCase(field, "registered_at")) {
            if (registered_at != null) return error.DuplicateField;
            registered_at = try parseTimestamp(value);
        } else if (std.ascii.eqlIgnoreCase(field, "last_used_at")) {
            if (last_used_at != null) return error.DuplicateField;
            last_used_at = try parseTimestamp(value);
        } else if (std.ascii.eqlIgnoreCase(field, "description")) {
            if (description != null) return error.DuplicateField;
            try validateDescription(value);
            description = try allocator.dupe(u8, value);
        } else if (std.ascii.eqlIgnoreCase(field, "flags")) {
            try parseFlags(allocator, value, &flags);
        } else if (std.mem.startsWith(u8, field, "setting.")) {
            const key = field["setting.".len..];
            try appendSetting(allocator, key, value, &settings);
        } else if (std.ascii.eqlIgnoreCase(field, "successor")) {
            if (successor != null) return error.DuplicateField;
            try validateSuccessor(value);
            successor = try allocator.dupe(u8, value);
        } else {
            return error.UnknownField;
        }
    }

    if (!saw_line) return error.EmptyInput;

    const owned_flags = try flags.toOwnedSlice(allocator);
    errdefer {
        for (owned_flags) |flag| allocator.free(flag);
        allocator.free(owned_flags);
    }

    const owned_settings = try settings.toOwnedSlice(allocator);
    errdefer {
        for (owned_settings) |setting| {
            allocator.free(setting.key);
            allocator.free(setting.value);
        }
        allocator.free(owned_settings);
    }

    return .{
        .channel = channel orelse return error.MissingChannel,
        .founder = founder orelse return error.MissingFounder,
        .registered_at = registered_at orelse return error.MissingRegisteredAt,
        .last_used_at = last_used_at,
        .description = description,
        .flags = owned_flags,
        .settings = owned_settings,
        .successor = successor,
    };
}

pub fn renderInfo(
    allocator: std.mem.Allocator,
    ctx: RenderContext,
    record: ChannelRecord,
) ChannelInfoError!RenderedInfo {
    try validateContext(ctx);
    try record.validate();

    var lines: std.ArrayListUnmanaged([]u8) = .empty;
    errdefer {
        for (lines.items) |line| allocator.free(line);
        lines.deinit(allocator);
    }

    try appendInfoLines(allocator, &lines, ctx, record);
    return .{ .lines = try lines.toOwnedSlice(allocator) };
}

pub fn appendInfoLines(
    allocator: std.mem.Allocator,
    lines: *std.ArrayListUnmanaged([]u8),
    ctx: RenderContext,
    record: ChannelRecord,
) ChannelInfoError!void {
    try validateContext(ctx);
    try record.validate();

    try appendLine(allocator, lines, ctx, .RPL_INFOSTART, record.channel, "Channel information follows");

    var buf: [256]u8 = undefined;
    try appendLine(
        allocator,
        lines,
        ctx,
        .RPL_INFO,
        record.channel,
        std.fmt.bufPrint(&buf, "Channel: {s}", .{record.channel}) catch return error.OutputTooSmall,
    );
    try appendLine(
        allocator,
        lines,
        ctx,
        .RPL_INFO,
        record.channel,
        std.fmt.bufPrint(&buf, "Founder: {s}", .{record.founder}) catch return error.OutputTooSmall,
    );
    try appendLine(
        allocator,
        lines,
        ctx,
        .RPL_INFO,
        record.channel,
        std.fmt.bufPrint(&buf, "Registered: {d}", .{record.registered_at}) catch return error.OutputTooSmall,
    );

    if (record.last_used_at) |last_used_at| {
        try appendLine(
            allocator,
            lines,
            ctx,
            .RPL_INFO,
            record.channel,
            std.fmt.bufPrint(&buf, "Last used: {d}", .{last_used_at}) catch return error.OutputTooSmall,
        );
    }

    if (record.description) |description| {
        try appendJoinedLine(allocator, lines, ctx, record.channel, "Description: ", &.{description});
    }

    if (record.flags.len > 0) {
        try appendJoinedLine(allocator, lines, ctx, record.channel, "Flags: ", record.flags);
    }

    for (record.settings) |setting| {
        const text = try std.fmt.allocPrint(allocator, "Setting {s}: {s}", .{ setting.key, setting.value });
        defer allocator.free(text);
        try appendLine(allocator, lines, ctx, .RPL_INFO, record.channel, text);
    }

    if (record.successor) |successor| {
        try appendLine(
            allocator,
            lines,
            ctx,
            .RPL_INFO,
            record.channel,
            std.fmt.bufPrint(&buf, "Successor: {s}", .{successor}) catch return error.OutputTooSmall,
        );
    }

    try appendLine(allocator, lines, ctx, .RPL_ENDOFINFO, record.channel, "End of channel information");
}

pub fn freeAppendedLines(allocator: std.mem.Allocator, lines: []const []u8) void {
    for (lines) |line| allocator.free(line);
}

fn appendLine(
    allocator: std.mem.Allocator,
    lines: *std.ArrayListUnmanaged([]u8),
    ctx: RenderContext,
    numeric: ChannelInfoNumeric,
    channel: []const u8,
    trailing: []const u8,
) ChannelInfoError!void {
    const ending: []const u8 = if (ctx.include_crlf) "\r\n" else "";
    const line = try std.fmt.allocPrint(
        allocator,
        ":{s} {s} {s} {s} :{s}{s}",
        .{ ctx.server_name, numeric.format(), ctx.requester, channel, trailing, ending },
    );
    errdefer allocator.free(line);
    try lines.append(allocator, line);
}

fn appendJoinedLine(
    allocator: std.mem.Allocator,
    lines: *std.ArrayListUnmanaged([]u8),
    ctx: RenderContext,
    channel: []const u8,
    prefix: []const u8,
    items: []const []const u8,
) ChannelInfoError!void {
    var body: std.ArrayListUnmanaged(u8) = .empty;
    defer body.deinit(allocator);
    try body.appendSlice(allocator, prefix);
    for (items, 0..) |item, idx| {
        if (idx != 0) try body.append(allocator, ' ');
        try body.appendSlice(allocator, item);
    }
    try appendLine(allocator, lines, ctx, .RPL_INFO, channel, body.items);
}

fn parseFlags(
    allocator: std.mem.Allocator,
    text: []const u8,
    flags: *std.ArrayListUnmanaged([]u8),
) ParseError!void {
    if (text.len == 0) return;
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |raw| {
        const flag = std.mem.trim(u8, raw, " \t");
        try validateFlag(flag);
        const owned = try allocator.dupe(u8, flag);
        errdefer allocator.free(owned);
        try flags.append(allocator, owned);
    }
}

fn appendSetting(
    allocator: std.mem.Allocator,
    key: []const u8,
    value: []const u8,
    settings: *std.ArrayListUnmanaged(OwnedChannelRecord.OwnedSetting),
) ParseError!void {
    try validateSettingKey(key);
    try validateSettingValue(value);
    const owned_key = try allocator.dupe(u8, key);
    errdefer allocator.free(owned_key);
    const owned_value = try allocator.dupe(u8, value);
    errdefer allocator.free(owned_value);
    try settings.append(allocator, .{ .key = owned_key, .value = owned_value });
}

fn ownedSettingsAsBorrowed(settings: []const OwnedChannelRecord.OwnedSetting) []const Setting {
    if (@sizeOf(OwnedChannelRecord.OwnedSetting) != @sizeOf(Setting)) {
        @compileError("owned and borrowed setting layouts must match");
    }
    return @ptrCast(settings);
}

fn parseTimestamp(text: []const u8) ParseError!i64 {
    const parsed = std.fmt.parseInt(i64, text, 10) catch return error.InvalidInteger;
    try validateTimestamp(parsed);
    return parsed;
}

fn validateContext(ctx: RenderContext) ChannelInfoError!void {
    if (ctx.server_name.len == 0) return error.EmptyServerName;
    if (ctx.server_name.len > max_server_bytes) return error.ServerNameTooLong;
    if (!isIrcMiddle(ctx.server_name)) return error.InvalidServerName;

    if (ctx.requester.len == 0) return error.EmptyRequester;
    if (ctx.requester.len > max_requester_bytes) return error.RequesterTooLong;
    if (!isIrcMiddle(ctx.requester)) return error.InvalidRequester;
}

fn validateChannel(channel: []const u8) ChannelInfoError!void {
    if (channel.len == 0) return error.EmptyChannel;
    if (channel.len > max_channel_bytes) return error.ChannelTooLong;
    if (channel[0] != '#' and channel[0] != '&') return error.InvalidChannel;
    if (!isIrcMiddle(channel)) return error.InvalidChannel;
}

fn validateSuccessor(successor: []const u8) ChannelInfoError!void {
    if (successor.len == 0) return;
    if (successor.len > max_channel_bytes) return error.SuccessorTooLong;
    if (successor[0] != '#' and successor[0] != '&') return error.InvalidSuccessor;
    if (!isIrcMiddle(successor)) return error.InvalidSuccessor;
}

fn validateAccount(
    account: []const u8,
    empty_error: ChannelInfoError,
    too_long_error: ChannelInfoError,
    invalid_error: ChannelInfoError,
) ChannelInfoError!void {
    if (account.len == 0) return empty_error;
    if (account.len > max_account_bytes) return too_long_error;
    if (!isIrcMiddle(account)) return invalid_error;
}

fn validateTimestamp(timestamp: i64) ChannelInfoError!void {
    if (timestamp < 0) return error.InvalidTimestamp;
}

fn validateDescription(description: []const u8) ChannelInfoError!void {
    if (description.len > max_description_bytes) return error.DescriptionTooLong;
    if (hasLineBreakOrNul(description)) return error.InvalidDescription;
}

fn validateFlag(flag: []const u8) ChannelInfoError!void {
    if (flag.len == 0) return error.EmptyFlag;
    if (flag.len > max_flag_bytes) return error.FlagTooLong;
    if (!isToken(flag)) return error.InvalidFlag;
}

fn validateSettingKey(key: []const u8) ChannelInfoError!void {
    if (key.len == 0) return error.EmptySettingKey;
    if (key.len > max_setting_key_bytes) return error.SettingKeyTooLong;
    if (!isToken(key)) return error.InvalidSettingKey;
}

fn validateSettingValue(value: []const u8) ChannelInfoError!void {
    if (value.len > max_setting_value_bytes) return error.SettingValueTooLong;
    if (hasLineBreakOrNul(value)) return error.InvalidSettingValue;
}

fn isIrcMiddle(value: []const u8) bool {
    for (value) |byte| {
        if (byte <= ' ' or byte == 0x7f) return false;
    }
    return true;
}

fn isToken(value: []const u8) bool {
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        if (byte == '-' or byte == '_') continue;
        return false;
    }
    return true;
}

fn hasLineBreakOrNul(value: []const u8) bool {
    return std.mem.indexOfAny(u8, value, "\r\n\x00") != null;
}

const testing = std.testing;

fn sampleRecord() ChannelRecord {
    const flags = [_][]const u8{ "private", "secure", "guarded" };
    const settings = [_]Setting{
        .{ .key = "mlock", .value = "+nt" },
        .{ .key = "entrymsg", .value = "Welcome to Orochi" },
    };
    return .{
        .channel = "#orochi",
        .founder = "alice",
        .registered_at = 1_700_000_000,
        .last_used_at = 1_700_000_900,
        .description = "Pure-Zig IRC daemon work",
        .flags = &flags,
        .settings = &settings,
        .successor = "#orochi-next",
    };
}

test "numeric constants are the standard INFO reply family" {
    try testing.expectEqual(@as(u16, 373), ChannelInfoNumeric.RPL_INFOSTART.code());
    try testing.expectEqual(@as(u16, 371), ChannelInfoNumeric.RPL_INFO.code());
    try testing.expectEqual(@as(u16, 374), ChannelInfoNumeric.RPL_ENDOFINFO.code());
    try testing.expectEqualStrings("RPL_INFO", ChannelInfoNumeric.RPL_INFO.tag());
    try testing.expectEqualStrings("374", ChannelInfoNumeric.RPL_ENDOFINFO.format());
}

test "record helper finds flags and settings case-insensitively" {
    const record = sampleRecord();
    try testing.expect(record.hasFlag("SECURE"));
    try testing.expect(!record.hasFlag("missing"));
    try testing.expectEqualStrings("+nt", record.settingValue("MLOCK").?);
    try testing.expect(record.settingValue("unknown") == null);
}

test "renderer emits ordered RPL-style channel info lines" {
    var rendered = try renderInfo(testing.allocator, .{
        .server_name = "irc.example.test",
        .requester = "bob",
    }, sampleRecord());
    defer rendered.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 11), rendered.lines.len);
    try testing.expectEqualStrings(":irc.example.test 373 bob #orochi :Channel information follows\r\n", rendered.lines[0]);
    try testing.expectEqualStrings(":irc.example.test 371 bob #orochi :Channel: #orochi\r\n", rendered.lines[1]);
    try testing.expectEqualStrings(":irc.example.test 371 bob #orochi :Founder: alice\r\n", rendered.lines[2]);
    try testing.expectEqualStrings(":irc.example.test 371 bob #orochi :Registered: 1700000000\r\n", rendered.lines[3]);
    try testing.expectEqualStrings(":irc.example.test 371 bob #orochi :Last used: 1700000900\r\n", rendered.lines[4]);
    try testing.expectEqualStrings(":irc.example.test 371 bob #orochi :Description: Pure-Zig IRC daemon work\r\n", rendered.lines[5]);
    try testing.expectEqualStrings(":irc.example.test 371 bob #orochi :Flags: private secure guarded\r\n", rendered.lines[6]);
    try testing.expectEqualStrings(":irc.example.test 371 bob #orochi :Setting mlock: +nt\r\n", rendered.lines[7]);
    try testing.expectEqualStrings(":irc.example.test 371 bob #orochi :Setting entrymsg: Welcome to Orochi\r\n", rendered.lines[8]);
    try testing.expectEqualStrings(":irc.example.test 371 bob #orochi :Successor: #orochi-next\r\n", rendered.lines[9]);
    try testing.expectEqualStrings(":irc.example.test 374 bob #orochi :End of channel information\r\n", rendered.lines[10]);
}

test "renderer appends an end line after optional fields" {
    var rendered = try renderInfo(testing.allocator, .{
        .server_name = "irc.example.test",
        .requester = "bob",
    }, .{
        .channel = "#small",
        .founder = "alice",
        .registered_at = 42,
    });
    defer rendered.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 5), rendered.lines.len);
    try testing.expectEqualStrings(":irc.example.test 374 bob #small :End of channel information\r\n", rendered.lines[4]);
}

test "renderer can omit CRLF for queue-owned framing" {
    var rendered = try renderInfo(testing.allocator, .{
        .server_name = "irc.example.test",
        .requester = "bob",
        .include_crlf = false,
    }, .{
        .channel = "#small",
        .founder = "alice",
        .registered_at = 42,
    });
    defer rendered.deinit(testing.allocator);

    try testing.expectEqualStrings(":irc.example.test 373 bob #small :Channel information follows", rendered.lines[0]);
    try testing.expectEqualStrings(":irc.example.test 374 bob #small :End of channel information", rendered.lines[4]);
}

test "appendInfoLines can extend a caller-owned list" {
    var lines: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (lines.items) |line| testing.allocator.free(line);
        lines.deinit(testing.allocator);
    }

    try appendInfoLines(testing.allocator, &lines, .{
        .server_name = "irc.example.test",
        .requester = "bob",
    }, .{
        .channel = "#small",
        .founder = "alice",
        .registered_at = 42,
    });

    try testing.expectEqual(@as(usize, 5), lines.items.len);
    try testing.expectEqualStrings(":irc.example.test 371 bob #small :Registered: 42\r\n", lines.items[3]);
}

test "parser reads a full key-value channel record" {
    var owned = try parseRecord(testing.allocator,
        \\channel=#orochi
        \\founder=Alice
        \\registered_at=1700000000
        \\last_used_at=1700000900
        \\description=Pure-Zig IRC daemon work
        \\flags=private, secure,guarded
        \\setting.mlock=+nt
        \\setting.entrymsg=Welcome to Orochi
        \\successor=#orochi-next
    );
    defer owned.deinit(testing.allocator);

    const record = owned.asRecord();
    try testing.expectEqualStrings("#orochi", record.channel);
    try testing.expectEqualStrings("Alice", record.founder);
    try testing.expect(record.hasFlag("SECURE"));
    try testing.expectEqualStrings("Welcome to Orochi", record.settingValue("entrymsg").?);
    try testing.expectEqualStrings("#orochi-next", record.successor.?);
}

test "parsed records render through the public formatter" {
    var owned = try parseRecord(testing.allocator,
        \\channel=#zig
        \\founder=alice
        \\registered_at=7
        \\description=dev channel
        \\flags=public
        \\setting.mlock=+nt
    );
    defer owned.deinit(testing.allocator);

    var rendered = try renderInfo(testing.allocator, .{
        .server_name = "irc.example.test",
        .requester = "bob",
        .include_crlf = false,
    }, owned.asRecord());
    defer rendered.deinit(testing.allocator);

    try testing.expectEqualStrings(":irc.example.test 371 bob #zig :Description: dev channel", rendered.lines[4]);
    try testing.expectEqualStrings(":irc.example.test 371 bob #zig :Flags: public", rendered.lines[5]);
    try testing.expectEqualStrings(":irc.example.test 371 bob #zig :Setting mlock: +nt", rendered.lines[6]);
}

test "parser rejects missing required fields and duplicates" {
    try testing.expectError(error.MissingFounder, parseRecord(testing.allocator,
        \\channel=#x
        \\registered_at=1
    ));
    try testing.expectError(error.DuplicateField, parseRecord(testing.allocator,
        \\channel=#x
        \\channel=#y
        \\founder=alice
        \\registered_at=1
    ));
}

test "parser rejects invalid field names and values" {
    try testing.expectError(error.UnknownField, parseRecord(testing.allocator,
        \\channel=#x
        \\founder=alice
        \\registered_at=1
        \\service=not-real
    ));
    try testing.expectError(error.InvalidDescription, parseRecord(testing.allocator, "channel=#x\nfounder=alice\nregistered_at=1\ndescription=bad\rline"));
    try testing.expectError(error.InvalidFlag, parseRecord(testing.allocator,
        \\channel=#x
        \\founder=alice
        \\registered_at=1
        \\flags=good,bad flag
    ));
    try testing.expectError(error.InvalidSettingKey, parseRecord(testing.allocator,
        \\channel=#x
        \\founder=alice
        \\registered_at=1
        \\setting.bad key=value
    ));
}

test "validation prevents IRC line injection" {
    try testing.expectError(error.InvalidServerName, renderInfo(testing.allocator, .{
        .server_name = "irc.example.test\r\n:evil",
        .requester = "bob",
    }, .{
        .channel = "#small",
        .founder = "alice",
        .registered_at = 42,
    }));
    try testing.expectError(error.InvalidDescription, renderInfo(testing.allocator, .{
        .server_name = "irc.example.test",
        .requester = "bob",
    }, .{
        .channel = "#small",
        .founder = "alice",
        .registered_at = 42,
        .description = "bad\nline",
    }));
    try testing.expectError(error.InvalidSettingValue, renderInfo(testing.allocator, .{
        .server_name = "irc.example.test",
        .requester = "bob",
    }, .{
        .channel = "#small",
        .founder = "alice",
        .registered_at = 42,
        .settings = &.{.{ .key = "mlock", .value = "+nt\r\nMODE #small +o mallory" }},
    }));
}

test "validation rejects invalid channel, founder, timestamp, successor" {
    try testing.expectError(error.InvalidChannel, sampleInvalid(.{ .channel = "not-a-channel" }));
    try testing.expectError(error.InvalidFounder, sampleInvalid(.{ .founder = "bad founder" }));
    try testing.expectError(error.InvalidTimestamp, sampleInvalid(.{ .registered_at = -1 }));
    try testing.expectError(error.InvalidSuccessor, sampleInvalid(.{ .successor = "not-a-channel" }));
}

const InvalidOverride = struct {
    channel: []const u8 = "#x",
    founder: []const u8 = "alice",
    registered_at: i64 = 1,
    successor: ?[]const u8 = null,
};

fn sampleInvalid(override: InvalidOverride) ChannelInfoError!void {
    const record = ChannelRecord{
        .channel = override.channel,
        .founder = override.founder,
        .registered_at = override.registered_at,
        .successor = override.successor,
    };
    return record.validate();
}
