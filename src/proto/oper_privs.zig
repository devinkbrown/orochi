//! Operator privilege class protocol helpers.
//!
//! This file is pure protocol glue: class names resolve to the privilege set
//! type owned by `daemon/oper.zig`, GRANT is parsed/rendered as borrowed slices,
//! and RPL_PRIVS is built into caller-owned storage.
const std = @import("std");
const numeric = @import("numeric.zig");
const root = @import("root");
const oper = if (@hasDecl(root, "daemon")) root.daemon.oper else StandaloneOper;

pub const Privilege = oper.Privilege;
pub const OperPrivileges = oper.OperPrivileges;

const StandaloneOper = struct {
    const StandalonePrivilege = enum {
        server_rehash,
        server_restart,
        server_shutdown,
        client_moderate,
        channel_moderate,
        service_admin,
        mesh_admin,
        event_subscribe,
        audit_read,
        oper_grant,
    };

    pub const Privilege = StandalonePrivilege;

    pub const OperPrivileges = struct {
        const Self = @This();

        set: std.EnumSet(StandalonePrivilege) = .empty,

        pub const empty: Self = .{};
        pub const full: Self = .{ .set = std.EnumSet(StandalonePrivilege).full };

        pub fn initMany(privileges: []const StandalonePrivilege) Self {
            return .{ .set = std.EnumSet(StandalonePrivilege).initMany(privileges) };
        }

        pub fn insert(self: *Self, privilege: StandalonePrivilege) void {
            self.set.insert(privilege);
        }

        pub fn has(self: Self, privilege: StandalonePrivilege) bool {
            return self.set.contains(privilege);
        }

        pub fn count(self: Self) usize {
            return self.set.count();
        }
    };
};

pub const DEFAULT_MAX_NICK_BYTES: usize = 64;
pub const DEFAULT_MAX_CLASS_BYTES: usize = 64;
pub const DEFAULT_MAX_SERVER_NAME_BYTES: usize = 255;

pub const Params = struct {
    max_nick_bytes: usize = DEFAULT_MAX_NICK_BYTES,
    max_class_bytes: usize = DEFAULT_MAX_CLASS_BYTES,
    max_server_name_bytes: usize = DEFAULT_MAX_SERVER_NAME_BYTES,
};

pub const Error = error{
    MissingNick,
    MissingPrivset,
    TooManyParameters,
    InvalidCommand,
    InvalidNick,
    NickTooLong,
    InvalidClass,
    ClassTooLong,
    DuplicateClass,
    EmptyPrivileges,
    UnknownClass,
    InvalidServerName,
    ServerNameTooLong,
    OutputTooSmall,
};

pub const PrivilegeClass = struct {
    name: []const u8,
    privileges: OperPrivileges,
};

pub const ClassTable = struct {
    classes: []const PrivilegeClass,

    pub fn init(classes: []const PrivilegeClass) Error!ClassTable {
        const table = ClassTable{ .classes = classes };
        try table.validate(.{});
        return table;
    }

    pub fn initWithParams(comptime params: Params, classes: []const PrivilegeClass) Error!ClassTable {
        const table = ClassTable{ .classes = classes };
        try table.validate(params);
        return table;
    }

    pub fn validate(self: ClassTable, comptime params: Params) Error!void {
        for (self.classes, 0..) |class, index| {
            try validateClassNameWith(params, class.name);
            if (class.privileges.count() == 0) return error.EmptyPrivileges;

            for (self.classes[0..index]) |previous| {
                if (classNameEqual(previous.name, class.name)) return error.DuplicateClass;
            }
        }
    }

    pub fn resolve(self: ClassTable, class_name: []const u8) Error!OperPrivileges {
        try validateClassName(class_name);
        for (self.classes) |class| {
            if (classNameEqual(class.name, class_name)) return class.privileges;
        }
        return error.UnknownClass;
    }
};

pub const Grant = struct {
    nick: []const u8,
    privset: []const u8,
};

pub const PrivsReply = struct {
    server_name: []const u8,
    requester: []const u8,
    client: []const u8,
    privileges: OperPrivileges,
};

pub fn resolveClass(table: ClassTable, class_name: []const u8) Error!OperPrivileges {
    return table.resolve(class_name);
}

pub fn parseGrantParams(params: []const []const u8) Error!Grant {
    return parseGrantParamsWith(.{}, params);
}

pub fn parseGrantParamsWith(comptime bounds: Params, params: []const []const u8) Error!Grant {
    if (params.len == 0) return error.MissingNick;
    if (params.len == 1) return error.MissingPrivset;
    if (params.len > 2) return error.TooManyParameters;

    try validateNickWith(bounds, params[0]);
    try validateClassNameWith(bounds, params[1]);
    return .{ .nick = params[0], .privset = params[1] };
}

pub fn parseGrantLine(line: []const u8) Error!Grant {
    return parseGrantLineWith(.{}, line);
}

pub fn parseGrantLineWith(comptime bounds: Params, line: []const u8) Error!Grant {
    var tokens: [3][]const u8 = undefined;
    var count: usize = 0;
    var it = std.mem.tokenizeAny(u8, line, " \r\n");

    const command = it.next() orelse return error.InvalidCommand;
    if (!std.ascii.eqlIgnoreCase(command, "GRANT")) return error.InvalidCommand;

    while (it.next()) |token| {
        if (count >= tokens.len) return error.TooManyParameters;
        tokens[count] = token;
        count += 1;
    }
    return parseGrantParamsWith(bounds, tokens[0..count]);
}

pub fn buildGrantCommand(out: []u8, nick: []const u8, privset: []const u8) Error![]const u8 {
    return buildGrantCommandWith(.{}, out, nick, privset);
}

pub fn buildGrantCommandWith(
    comptime bounds: Params,
    out: []u8,
    nick: []const u8,
    privset: []const u8,
) Error![]const u8 {
    try validateNickWith(bounds, nick);
    try validateClassNameWith(bounds, privset);

    var b = LineBuilder.init(out);
    try b.appendBytes("GRANT ");
    try b.appendParam(nick);
    try b.appendByte(' ');
    try b.appendParam(privset);
    return b.slice();
}

pub fn buildPrivsReply(out: []u8, reply: PrivsReply) Error![]const u8 {
    return buildPrivsReplyWith(.{}, out, reply);
}

pub fn buildPrivsReplyWith(comptime bounds: Params, out: []u8, reply: PrivsReply) Error![]const u8 {
    try validateServerNameWith(bounds, reply.server_name);
    try validateNickWith(bounds, reply.requester);
    try validateNickWith(bounds, reply.client);
    if (reply.privileges.count() == 0) return error.EmptyPrivileges;

    var b = LineBuilder.init(out);
    try b.numericPrefix(.RPL_PRIVS, reply.server_name, reply.requester);
    try b.spaceParam(reply.client);
    try b.appendBytes(" :");
    try appendPrivilegeList(&b, reply.privileges);
    return b.slice();
}

pub fn validateNick(nick: []const u8) Error!void {
    return validateNickWith(.{}, nick);
}

pub fn validateClassName(class_name: []const u8) Error!void {
    return validateClassNameWith(.{}, class_name);
}

fn appendPrivilegeList(b: *LineBuilder, privileges: OperPrivileges) Error!void {
    var wrote = false;
    inline for (@typeInfo(Privilege).@"enum".fields) |field| {
        const privilege: Privilege = @field(Privilege, field.name);
        if (privileges.has(privilege)) {
            if (wrote) try b.appendByte(' ');
            try b.appendBytes(field.name);
            wrote = true;
        }
    }
}

fn validateNickWith(comptime bounds: Params, nick: []const u8) Error!void {
    if (nick.len == 0) return error.InvalidNick;
    if (nick.len > bounds.max_nick_bytes) return error.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return error.InvalidNick;
    }
}

fn validateClassNameWith(comptime bounds: Params, class_name: []const u8) Error!void {
    if (class_name.len == 0) return error.InvalidClass;
    if (class_name.len > bounds.max_class_bytes) return error.ClassTooLong;
    for (class_name) |ch| {
        const ok = (ch >= 'A' and ch <= 'Z') or
            (ch >= 'a' and ch <= 'z') or
            (ch >= '0' and ch <= '9') or
            ch == '_' or ch == '-' or ch == '.';
        if (!ok) return error.InvalidClass;
    }
}

fn validateServerNameWith(comptime bounds: Params, server_name: []const u8) Error!void {
    if (server_name.len == 0) return error.InvalidServerName;
    if (server_name.len > bounds.max_server_name_bytes) return error.ServerNameTooLong;
    for (server_name) |ch| {
        if (!validServerNameByte(ch)) return error.InvalidServerName;
    }
}

fn classNameEqual(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn validNickByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '[', ']', '\\', '`', '_', '^', '{', '|', '}', '-' => true,
        else => false,
    };
}

fn validServerNameByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', ':', '[', ']', '/' => true,
        else => false,
    };
}

const LineBuilder = struct {
    out: []u8,
    len: usize = 0,

    fn init(out: []u8) LineBuilder {
        return .{ .out = out };
    }

    fn slice(self: *const LineBuilder) []const u8 {
        return self.out[0..self.len];
    }

    fn numericPrefix(self: *LineBuilder, code: numeric.Numeric, server_name: []const u8, requester: []const u8) Error!void {
        var code_buf: [3]u8 = undefined;
        try self.appendByte(':');
        try self.appendParam(server_name);
        try self.appendByte(' ');
        try self.appendBytes(numeric.formatCode(code, &code_buf));
        try self.appendByte(' ');
        try self.appendParam(requester);
    }

    fn spaceParam(self: *LineBuilder, param: []const u8) Error!void {
        try self.appendByte(' ');
        try self.appendParam(param);
    }

    fn appendParam(self: *LineBuilder, param: []const u8) Error!void {
        for (param) |ch| {
            if (ch <= 0x20 or ch == 0x7f or ch == ':') return error.InvalidNick;
        }
        try self.appendBytes(param);
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) Error!void {
        if (self.out.len - self.len < bytes.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) Error!void {
        if (self.out.len - self.len < 1) return error.OutputTooSmall;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

test "class resolution returns operator privilege set" {
    const allocator = std.testing.allocator;
    _ = allocator;

    const classes = [_]PrivilegeClass{
        .{
            .name = "netadmin",
            .privileges = OperPrivileges.initMany(&.{ .server_rehash, .oper_grant }),
        },
        .{
            .name = "services",
            .privileges = OperPrivileges.initMany(&.{.service_admin}),
        },
    };
    const table = try ClassTable.init(&classes);

    const resolved = try table.resolve("NETADMIN");
    try std.testing.expect(resolved.has(.server_rehash));
    try std.testing.expect(resolved.has(.oper_grant));
    try std.testing.expect(!resolved.has(.service_admin));
}

test "GRANT parse and build use nick plus privilege-set class" {
    const allocator = std.testing.allocator;
    _ = allocator;

    const parsed = try parseGrantLine("GRANT alice netadmin");
    try std.testing.expectEqualStrings("alice", parsed.nick);
    try std.testing.expectEqualStrings("netadmin", parsed.privset);

    var buf: [64]u8 = undefined;
    const built = try buildGrantCommand(&buf, parsed.nick, parsed.privset);
    try std.testing.expectEqualStrings("GRANT alice netadmin", built);

    try std.testing.expectError(error.MissingPrivset, parseGrantLine("GRANT alice"));
}

test "RPL_PRIVS bytes list client privileges" {
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 256);
    defer allocator.free(out);

    const line = try buildPrivsReply(out, .{
        .server_name = "irc.example",
        .requester = "alice",
        .client = "bob",
        .privileges = OperPrivileges.initMany(&.{ .server_rehash, .oper_grant }),
    });

    try std.testing.expectEqualStrings(
        ":irc.example 270 alice bob :server_rehash oper_grant",
        line,
    );
}

test "unknown class reject" {
    const allocator = std.testing.allocator;
    _ = allocator;

    const classes = [_]PrivilegeClass{.{
        .name = "netadmin",
        .privileges = OperPrivileges.initMany(&.{.server_rehash}),
    }};
    const table = try ClassTable.init(&classes);

    try std.testing.expectError(error.UnknownClass, table.resolve("missing"));
    try std.testing.expectError(error.InvalidClass, table.resolve("bad class"));
}
