//! Daemon configuration and a strict TOML-subset parser.
//!
//! Supported syntax is intentionally small: `[serverinfo]`, `[limits]`, and
//! repeated `[[listeners]]`, `[[opers]]`, `[[classes]]` tables; `key = value`;
//! quoted strings without escapes; unsigned decimal integers; lowercase bools;
//! and arrays of quoted strings. Unsupported TOML features include dotted keys,
//! inline tables, floats, dates, multiline strings, escape sequences, and mixed
//! arrays. Parsed scalar strings borrow from the input buffer; keep it alive for
//! the lifetime of `Config`.
const std = @import("std");

/// Errors produced while parsing or validating daemon configuration.
pub const ParseError = std.mem.Allocator.Error || error{
    DuplicateKey,
    DuplicateTable,
    EmptyKey,
    InvalidArray,
    InvalidBoolean,
    InvalidInteger,
    InvalidKey,
    InvalidLimit,
    InvalidPort,
    InvalidString,
    InvalidTable,
    InvalidValue,
    MissingEquals,
    MissingRequiredField,
    TableRequired,
    TrailingCharacters,
    UnknownKey,
    UnknownTable,
    UnsupportedSyntax,
};

/// Server identity advertised to clients and peers.
pub const ServerInfo = struct {
    name: []const u8 = "",
    network: []const u8 = "",
    description: []const u8 = "Mizuchi IRC daemon",
};

/// Listener policy. TLS and WebSocket are orthogonal transport switches.
pub const Listener = struct {
    host: []const u8 = "0.0.0.0",
    port: u16 = 6667,
    tls: bool = false,
    websocket: bool = false,
};

/// Global resource ceilings.
pub const Limits = struct {
    max_clients: usize = 4096,
    max_channels: usize = 1024,
    sendq: usize = 1024 * 1024,
};

/// Operator account declaration. At least one credential must be configured.
pub const Oper = struct {
    name: []const u8 = "",
    flags: []const []const u8 = &.{},
    certfp: ?[]const u8 = null,
    pwhash: ?[]const u8 = null,
};

/// Connection class defaults used by listeners and future policy modules.
pub const Class = struct {
    name: []const u8 = "default",
    ping_interval: u32 = 60,
    sendq: usize = 1024 * 1024,
    max_clients: usize = 0,
};

/// Fully validated daemon configuration.
pub const Config = struct {
    allocator: std.mem.Allocator,
    serverinfo: ServerInfo,
    listeners: []Listener,
    limits: Limits,
    opers: []Oper,
    classes: []Class,

    pub fn deinit(self: *Config) void {
        for (self.opers) |oper| {
            if (oper.flags.len != 0) self.allocator.free(oper.flags);
        }
        self.allocator.free(self.listeners);
        self.allocator.free(self.opers);
        self.allocator.free(self.classes);
        self.* = .{
            .allocator = self.allocator,
            .serverinfo = .{},
            .listeners = &.{},
            .limits = .{},
            .opers = &.{},
            .classes = &.{},
        };
    }
};

/// Parse and validate a daemon configuration document.
pub fn parse(allocator: std.mem.Allocator, input: []const u8) ParseError!Config {
    var builder = Builder.init(allocator);
    errdefer builder.deinit();

    try builder.parse(input);
    const config = try builder.finish();
    builder.deinit();
    return config;
}

const Table = enum {
    root,
    serverinfo,
    limits,
    listener,
    oper,
    class,
};

const FieldBits = packed struct(u16) {
    name: bool = false,
    network: bool = false,
    description: bool = false,
    host: bool = false,
    port: bool = false,
    tls: bool = false,
    websocket: bool = false,
    flags: bool = false,
    certfp: bool = false,
    pwhash: bool = false,
    max_clients: bool = false,
    max_channels: bool = false,
    sendq: bool = false,
    ping_interval: bool = false,
    _pad: u2 = 0,
};

const ServerInfoDraft = struct {
    value: ServerInfo = .{},
    fields: FieldBits = .{},
};

const ListenerDraft = struct {
    value: Listener = .{},
    fields: FieldBits = .{},
};

const LimitsDraft = struct {
    value: Limits = .{},
    fields: FieldBits = .{},
};

const OperDraft = struct {
    value: Oper = .{},
    fields: FieldBits = .{},

    fn deinit(self: *OperDraft, allocator: std.mem.Allocator) void {
        if (self.value.flags.len != 0) allocator.free(self.value.flags);
        self.value.flags = &.{};
    }
};

const ClassDraft = struct {
    value: Class = .{},
    fields: FieldBits = .{},
};

const Builder = struct {
    allocator: std.mem.Allocator,
    table: Table = .root,
    serverinfo_seen: bool = false,
    limits_seen: bool = false,
    serverinfo: ServerInfoDraft = .{},
    limits: LimitsDraft = .{},
    listeners: std.ArrayList(ListenerDraft) = .empty,
    opers: std.ArrayList(OperDraft) = .empty,
    classes: std.ArrayList(ClassDraft) = .empty,

    fn init(allocator: std.mem.Allocator) Builder {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *Builder) void {
        for (self.opers.items) |*oper| oper.deinit(self.allocator);
        self.listeners.deinit(self.allocator);
        self.opers.deinit(self.allocator);
        self.classes.deinit(self.allocator);
    }

    fn parse(self: *Builder, input: []const u8) ParseError!void {
        var cursor: usize = 0;
        while (cursor <= input.len) {
            const start = cursor;
            while (cursor < input.len and input[cursor] != '\n') cursor += 1;
            const raw_line = input[start..cursor];
            if (cursor < input.len) cursor += 1 else cursor += 1;

            const line = std.mem.trim(u8, try stripComment(raw_line), " \t\r\n");
            if (line.len == 0) continue;

            if (line[0] == '[') {
                try self.setTable(line);
            } else {
                try self.setKeyValue(line);
            }
        }
    }

    fn setTable(self: *Builder, line: []const u8) ParseError!void {
        if (line.len < 3) return error.InvalidTable;

        if (std.mem.startsWith(u8, line, "[[")) {
            if (!std.mem.endsWith(u8, line, "]]")) return error.InvalidTable;
            const name = std.mem.trim(u8, line[2 .. line.len - 2], " \t");
            if (!isBareName(name)) return error.InvalidTable;

            if (std.mem.eql(u8, name, "listeners")) {
                try self.listeners.append(self.allocator, .{});
                self.table = .listener;
            } else if (std.mem.eql(u8, name, "opers")) {
                try self.opers.append(self.allocator, .{});
                self.table = .oper;
            } else if (std.mem.eql(u8, name, "classes")) {
                try self.classes.append(self.allocator, .{});
                self.table = .class;
            } else {
                return error.UnknownTable;
            }
            return;
        }

        if (!std.mem.endsWith(u8, line, "]")) return error.InvalidTable;
        const name = std.mem.trim(u8, line[1 .. line.len - 1], " \t");
        if (!isBareName(name)) return error.InvalidTable;

        if (std.mem.eql(u8, name, "serverinfo")) {
            if (self.serverinfo_seen) return error.DuplicateTable;
            self.serverinfo_seen = true;
            self.table = .serverinfo;
        } else if (std.mem.eql(u8, name, "limits")) {
            if (self.limits_seen) return error.DuplicateTable;
            self.limits_seen = true;
            self.table = .limits;
        } else {
            return error.UnknownTable;
        }
    }

    fn setKeyValue(self: *Builder, line: []const u8) ParseError!void {
        const equals = findEquals(line) orelse return error.MissingEquals;
        const key = std.mem.trim(u8, line[0..equals], " \t");
        const raw_value = std.mem.trim(u8, line[equals + 1 ..], " \t");

        if (key.len == 0) return error.EmptyKey;
        if (!isBareName(key)) return error.InvalidKey;
        if (raw_value.len == 0) return error.InvalidValue;

        switch (self.table) {
            .root => return error.TableRequired,
            .serverinfo => try self.setServerInfo(key, raw_value),
            .limits => try self.setLimits(key, raw_value),
            .listener => try self.setListener(key, raw_value),
            .oper => try self.setOper(key, raw_value),
            .class => try self.setClass(key, raw_value),
        }
    }

    fn setServerInfo(self: *Builder, key: []const u8, raw_value: []const u8) ParseError!void {
        if (std.mem.eql(u8, key, "name")) {
            if (self.serverinfo.fields.name) return error.DuplicateKey;
            self.serverinfo.value.name = try parseString(raw_value);
            self.serverinfo.fields.name = true;
        } else if (std.mem.eql(u8, key, "network")) {
            if (self.serverinfo.fields.network) return error.DuplicateKey;
            self.serverinfo.value.network = try parseString(raw_value);
            self.serverinfo.fields.network = true;
        } else if (std.mem.eql(u8, key, "description")) {
            if (self.serverinfo.fields.description) return error.DuplicateKey;
            self.serverinfo.value.description = try parseString(raw_value);
            self.serverinfo.fields.description = true;
        } else {
            return error.UnknownKey;
        }
    }

    fn setLimits(self: *Builder, key: []const u8, raw_value: []const u8) ParseError!void {
        if (std.mem.eql(u8, key, "max_clients")) {
            if (self.limits.fields.max_clients) return error.DuplicateKey;
            self.limits.value.max_clients = try parsePositiveUsize(raw_value);
            self.limits.fields.max_clients = true;
        } else if (std.mem.eql(u8, key, "max_channels")) {
            if (self.limits.fields.max_channels) return error.DuplicateKey;
            self.limits.value.max_channels = try parsePositiveUsize(raw_value);
            self.limits.fields.max_channels = true;
        } else if (std.mem.eql(u8, key, "sendq")) {
            if (self.limits.fields.sendq) return error.DuplicateKey;
            self.limits.value.sendq = try parsePositiveUsize(raw_value);
            self.limits.fields.sendq = true;
        } else {
            return error.UnknownKey;
        }
    }

    fn setListener(self: *Builder, key: []const u8, raw_value: []const u8) ParseError!void {
        if (self.listeners.items.len == 0) return error.TableRequired;
        var item = &self.listeners.items[self.listeners.items.len - 1];

        if (std.mem.eql(u8, key, "host")) {
            if (item.fields.host) return error.DuplicateKey;
            item.value.host = try parseString(raw_value);
            item.fields.host = true;
        } else if (std.mem.eql(u8, key, "port")) {
            if (item.fields.port) return error.DuplicateKey;
            item.value.port = try parsePort(raw_value);
            item.fields.port = true;
        } else if (std.mem.eql(u8, key, "tls")) {
            if (item.fields.tls) return error.DuplicateKey;
            item.value.tls = try parseBool(raw_value);
            item.fields.tls = true;
        } else if (std.mem.eql(u8, key, "websocket")) {
            if (item.fields.websocket) return error.DuplicateKey;
            item.value.websocket = try parseBool(raw_value);
            item.fields.websocket = true;
        } else {
            return error.UnknownKey;
        }
    }

    fn setOper(self: *Builder, key: []const u8, raw_value: []const u8) ParseError!void {
        if (self.opers.items.len == 0) return error.TableRequired;
        var item = &self.opers.items[self.opers.items.len - 1];

        if (std.mem.eql(u8, key, "name")) {
            if (item.fields.name) return error.DuplicateKey;
            item.value.name = try parseString(raw_value);
            item.fields.name = true;
        } else if (std.mem.eql(u8, key, "flags")) {
            if (item.fields.flags) return error.DuplicateKey;
            item.value.flags = try parseStringArray(self.allocator, raw_value);
            item.fields.flags = true;
        } else if (std.mem.eql(u8, key, "certfp")) {
            if (item.fields.certfp) return error.DuplicateKey;
            item.value.certfp = try parseString(raw_value);
            item.fields.certfp = true;
        } else if (std.mem.eql(u8, key, "pwhash")) {
            if (item.fields.pwhash) return error.DuplicateKey;
            item.value.pwhash = try parseString(raw_value);
            item.fields.pwhash = true;
        } else {
            return error.UnknownKey;
        }
    }

    fn setClass(self: *Builder, key: []const u8, raw_value: []const u8) ParseError!void {
        if (self.classes.items.len == 0) return error.TableRequired;
        var item = &self.classes.items[self.classes.items.len - 1];

        if (std.mem.eql(u8, key, "name")) {
            if (item.fields.name) return error.DuplicateKey;
            item.value.name = try parseString(raw_value);
            item.fields.name = true;
        } else if (std.mem.eql(u8, key, "ping_interval")) {
            if (item.fields.ping_interval) return error.DuplicateKey;
            item.value.ping_interval = try parsePositiveU32(raw_value);
            item.fields.ping_interval = true;
        } else if (std.mem.eql(u8, key, "sendq")) {
            if (item.fields.sendq) return error.DuplicateKey;
            item.value.sendq = try parsePositiveUsize(raw_value);
            item.fields.sendq = true;
        } else if (std.mem.eql(u8, key, "max_clients")) {
            if (item.fields.max_clients) return error.DuplicateKey;
            item.value.max_clients = try parseUsize(raw_value);
            item.fields.max_clients = true;
        } else {
            return error.UnknownKey;
        }
    }

    fn finish(self: *Builder) ParseError!Config {
        try validateServerInfo(self.serverinfo);
        try validateLimits(self.limits.value);

        if (self.classes.items.len == 0) try self.classes.append(self.allocator, .{});

        var config = Config{
            .allocator = self.allocator,
            .serverinfo = self.serverinfo.value,
            .listeners = &.{},
            .limits = self.limits.value,
            .opers = &.{},
            .classes = &.{},
        };
        errdefer config.deinit();

        config.listeners = try self.allocator.alloc(Listener, self.listeners.items.len);
        for (self.listeners.items, 0..) |listener, index| {
            try validateListener(listener.value);
            config.listeners[index] = listener.value;
        }

        config.classes = try self.allocator.alloc(Class, self.classes.items.len);
        for (self.classes.items, 0..) |class, index| {
            try validateClass(class.value);
            config.classes[index] = class.value;
        }

        config.opers = try self.allocator.alloc(Oper, self.opers.items.len);
        for (self.opers.items, 0..) |*oper, index| {
            try validateOper(oper.value);
            config.opers[index] = oper.value;
            oper.value.flags = &.{};
        }

        return config;
    }
};

fn stripComment(line: []const u8) ParseError![]const u8 {
    var quoted = false;
    for (line, 0..) |ch, index| {
        switch (ch) {
            '"' => quoted = !quoted,
            '\\' => if (quoted) return error.UnsupportedSyntax,
            '#' => if (!quoted) return line[0..index],
            0 => return error.InvalidString,
            else => {},
        }
    }
    if (quoted) return error.InvalidString;
    return line;
}

fn findEquals(line: []const u8) ?usize {
    var quoted = false;
    for (line, 0..) |ch, index| {
        switch (ch) {
            '"' => quoted = !quoted,
            '=' => if (!quoted) return index,
            else => {},
        }
    }
    return null;
}

fn parseString(raw: []const u8) ParseError![]const u8 {
    if (raw.len < 2 or raw[0] != '"' or raw[raw.len - 1] != '"') return error.InvalidString;
    const text = raw[1 .. raw.len - 1];
    for (text) |ch| {
        switch (ch) {
            0, '\n', '\r', '\t' => return error.InvalidString,
            '"', '\\' => return error.UnsupportedSyntax,
            else => if (ch < 0x20) return error.InvalidString,
        }
    }
    return text;
}

fn parseBool(raw: []const u8) ParseError!bool {
    if (std.mem.eql(u8, raw, "true")) return true;
    if (std.mem.eql(u8, raw, "false")) return false;
    return error.InvalidBoolean;
}

fn parseUsize(raw: []const u8) ParseError!usize {
    if (raw.len == 0 or raw[0] == '+') return error.InvalidInteger;
    return std.fmt.parseInt(usize, raw, 10) catch return error.InvalidInteger;
}

fn parsePositiveUsize(raw: []const u8) ParseError!usize {
    const value = try parseUsize(raw);
    if (value == 0) return error.InvalidLimit;
    return value;
}

fn parsePositiveU32(raw: []const u8) ParseError!u32 {
    if (raw.len == 0 or raw[0] == '+') return error.InvalidInteger;
    const value = std.fmt.parseInt(u32, raw, 10) catch return error.InvalidInteger;
    if (value == 0) return error.InvalidLimit;
    return value;
}

fn parsePort(raw: []const u8) ParseError!u16 {
    const value = try parseUsize(raw);
    if (value == 0 or value > 65535) return error.InvalidPort;
    return @intCast(value);
}

fn parseStringArray(allocator: std.mem.Allocator, raw: []const u8) ParseError![]const []const u8 {
    if (raw.len < 2 or raw[0] != '[' or raw[raw.len - 1] != ']') return error.InvalidArray;
    const body = raw[1 .. raw.len - 1];
    var values: std.ArrayList([]const u8) = .empty;
    errdefer values.deinit(allocator);

    var cursor: usize = 0;
    while (true) {
        cursor = skipSpaces(body, cursor);
        if (cursor == body.len) break;

        if (body[cursor] != '"') return error.InvalidArray;
        const start = cursor;
        cursor += 1;
        while (cursor < body.len and body[cursor] != '"') {
            if (body[cursor] == '\\') return error.UnsupportedSyntax;
            if (body[cursor] < 0x20) return error.InvalidString;
            cursor += 1;
        }
        if (cursor >= body.len) return error.InvalidString;
        const item = try parseString(body[start .. cursor + 1]);
        try values.append(allocator, item);
        cursor += 1;
        cursor = skipSpaces(body, cursor);

        if (cursor == body.len) break;
        if (body[cursor] != ',') return error.InvalidArray;
        cursor += 1;
        cursor = skipSpaces(body, cursor);
        if (cursor == body.len) return error.InvalidArray;
    }

    return values.toOwnedSlice(allocator);
}

fn skipSpaces(bytes: []const u8, start: usize) usize {
    var cursor = start;
    while (cursor < bytes.len and (bytes[cursor] == ' ' or bytes[cursor] == '\t')) {
        cursor += 1;
    }
    return cursor;
}

fn isBareName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |ch| {
        const ok = (ch >= 'a' and ch <= 'z') or
            (ch >= 'A' and ch <= 'Z') or
            (ch >= '0' and ch <= '9') or
            ch == '_';
        if (!ok) return false;
    }
    return true;
}

fn validateServerInfo(draft: ServerInfoDraft) ParseError!void {
    if (!draft.fields.name or !draft.fields.network) return error.MissingRequiredField;
    try validateNonEmptyString(draft.value.name);
    try validateNonEmptyString(draft.value.network);
    try validateNonEmptyString(draft.value.description);
}

fn validateListener(listener: Listener) ParseError!void {
    try validateNonEmptyString(listener.host);
    if (listener.port == 0) return error.InvalidPort;
}

fn validateLimits(limits: Limits) ParseError!void {
    if (limits.max_clients == 0 or limits.max_channels == 0 or limits.sendq == 0) {
        return error.InvalidLimit;
    }
}

fn validateOper(oper: Oper) ParseError!void {
    try validateNonEmptyString(oper.name);
    if (oper.certfp == null and oper.pwhash == null) return error.MissingRequiredField;
    for (oper.flags) |flag| try validateIdentifier(flag);
    if (oper.certfp) |certfp| try validateCertfp(certfp);
    if (oper.pwhash) |pwhash| try validateNonEmptyString(pwhash);
}

fn validateClass(class: Class) ParseError!void {
    try validateNonEmptyString(class.name);
    if (class.ping_interval == 0 or class.sendq == 0) return error.InvalidLimit;
}

fn validateNonEmptyString(text: []const u8) ParseError!void {
    if (text.len == 0) return error.MissingRequiredField;
    for (text) |ch| {
        if (ch == 0 or ch == '\r' or ch == '\n' or ch < 0x20) return error.InvalidString;
    }
}

fn validateIdentifier(text: []const u8) ParseError!void {
    if (!isBareName(text)) return error.InvalidString;
}

fn validateCertfp(text: []const u8) ParseError!void {
    if (text.len != 64 and text.len != 128) return error.InvalidString;
    for (text) |ch| {
        const hex = (ch >= '0' and ch <= '9') or
            (ch >= 'a' and ch <= 'f') or
            (ch >= 'A' and ch <= 'F');
        if (!hex) return error.InvalidString;
    }
}

test "parse representative daemon config" {
    const allocator = std.testing.allocator;
    const input =
        \\[serverinfo]
        \\name = "irc.mizuchi.test"
        \\network = "MizuchiNet"
        \\description = "test daemon"
        \\
        \\[[listeners]]
        \\host = "127.0.0.1"
        \\port = 6697
        \\tls = true
        \\websocket = false
        \\
        \\[limits]
        \\max_clients = 128
        \\max_channels = 64
        \\sendq = 262144
        \\
        \\[[opers]]
        \\name = "root"
        \\flags = ["rehash", "die"]
        \\certfp = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        \\
        \\[[classes]]
        \\name = "local"
        \\ping_interval = 45
        \\sendq = 131072
        \\max_clients = 32
    ;

    var config = try parse(allocator, input);
    defer config.deinit();

    try std.testing.expectEqualStrings("irc.mizuchi.test", config.serverinfo.name);
    try std.testing.expectEqualStrings("MizuchiNet", config.serverinfo.network);
    try std.testing.expectEqualStrings("test daemon", config.serverinfo.description);
    try std.testing.expectEqual(@as(usize, 1), config.listeners.len);
    try std.testing.expectEqualStrings("127.0.0.1", config.listeners[0].host);
    try std.testing.expectEqual(@as(u16, 6697), config.listeners[0].port);
    try std.testing.expect(config.listeners[0].tls);
    try std.testing.expect(!config.listeners[0].websocket);
    try std.testing.expectEqual(@as(usize, 128), config.limits.max_clients);
    try std.testing.expectEqual(@as(usize, 64), config.limits.max_channels);
    try std.testing.expectEqual(@as(usize, 262144), config.limits.sendq);
    try std.testing.expectEqual(@as(usize, 1), config.opers.len);
    try std.testing.expectEqualStrings("root", config.opers[0].name);
    try std.testing.expectEqual(@as(usize, 2), config.opers[0].flags.len);
    try std.testing.expectEqualStrings("rehash", config.opers[0].flags[0]);
    try std.testing.expectEqualStrings("die", config.opers[0].flags[1]);
    try std.testing.expectEqual(@as(usize, 1), config.classes.len);
    try std.testing.expectEqualStrings("local", config.classes[0].name);
    try std.testing.expectEqual(@as(u32, 45), config.classes[0].ping_interval);
    try std.testing.expectEqual(@as(usize, 131072), config.classes[0].sendq);
    try std.testing.expectEqual(@as(usize, 32), config.classes[0].max_clients);
}

test "reject malformed and missing required config" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.MissingEquals, parse(allocator,
        \\[serverinfo]
        \\name "irc.example"
    ));
    try std.testing.expectError(error.MissingRequiredField, parse(allocator,
        \\[serverinfo]
        \\name = "irc.example"
    ));
    try std.testing.expectError(error.InvalidPort, parse(allocator,
        \\[serverinfo]
        \\name = "irc.example"
        \\network = "ExampleNet"
        \\
        \\[[listeners]]
        \\port = 70000
    ));
    try std.testing.expectError(error.UnsupportedSyntax, parse(allocator,
        \\[serverinfo]
        \\name = "irc\n.example"
        \\network = "ExampleNet"
    ));
}

test "defaults fill optional daemon config" {
    const allocator = std.testing.allocator;
    const input =
        \\[serverinfo]
        \\name = "irc.example"
        \\network = "ExampleNet"
    ;

    var config = try parse(allocator, input);
    defer config.deinit();

    try std.testing.expectEqualStrings("Mizuchi IRC daemon", config.serverinfo.description);
    try std.testing.expectEqual(@as(usize, 0), config.listeners.len);
    try std.testing.expectEqual(@as(usize, 4096), config.limits.max_clients);
    try std.testing.expectEqual(@as(usize, 1024), config.limits.max_channels);
    try std.testing.expectEqual(@as(usize, 1024 * 1024), config.limits.sendq);
    try std.testing.expectEqual(@as(usize, 0), config.opers.len);
    try std.testing.expectEqual(@as(usize, 1), config.classes.len);
    try std.testing.expectEqualStrings("default", config.classes[0].name);
    try std.testing.expectEqual(@as(u32, 60), config.classes[0].ping_interval);
    try std.testing.expectEqual(@as(usize, 1024 * 1024), config.classes[0].sendq);
}
