//! Named per-channel role definitions for the Orochi daemon.
//!
//! This is a pure data/parser/logic module. It models real IRC command input
//! (`CHANROLE ...` or `CHANNEL ROLE ...`) and numeric reply codes; it does not
//! model daemon world state.

const std = @import("std");

const key_sep: u8 = 0x00;

pub const max_token_bytes: usize = 512;
pub const max_channel_bytes: usize = 200;
pub const max_account_bytes: usize = 64;
pub const max_role_bytes: usize = 32;
pub const max_flag_expr_bytes: usize = 256;

pub const Params = struct {
    max_token_bytes: usize = max_token_bytes,
    max_channel_bytes: usize = max_channel_bytes,
    max_account_bytes: usize = max_account_bytes,
    max_role_bytes: usize = max_role_bytes,
    max_flag_expr_bytes: usize = max_flag_expr_bytes,
};

pub const Error = error{
    EmptyToken,
    TokenTooLong,
    InvalidCommand,
    InvalidSubcommand,
    NeedMoreParams,
    TooManyParams,
    InvalidChannel,
    ChannelTooLong,
    InvalidAccount,
    AccountTooLong,
    InvalidRoleName,
    RoleNameTooLong,
    ReservedRoleName,
    InvalidFlag,
    EmptyFlagSet,
    FlagExpressionTooLong,
    NoSuchRole,
    OutputTooSmall,
} || std.mem.Allocator.Error;

pub const Numeric = enum(u16) {
    RPL_CHANROLE = 740,
    RPL_CHANROLELIST = 741,
    RPL_ENDOFCHANROLELIST = 742,
    RPL_CHANROLEASSIGN = 743,
    ERR_CHANROLE_NEEDMOREPARAMS = 940,
    ERR_CHANROLE_INVALIDPARAMS = 941,
    ERR_CHANROLE_NOSUCHROLE = 942,
    ERR_CHANROLE_TOOMANYPARAMS = 943,

    pub fn code(self: Numeric) u16 {
        return @intFromEnum(self);
    }

    pub fn token(self: Numeric) []const u8 {
        return switch (self) {
            .RPL_CHANROLE => "RPL_CHANROLE",
            .RPL_CHANROLELIST => "RPL_CHANROLELIST",
            .RPL_ENDOFCHANROLELIST => "RPL_ENDOFCHANROLELIST",
            .RPL_CHANROLEASSIGN => "RPL_CHANROLEASSIGN",
            .ERR_CHANROLE_NEEDMOREPARAMS => "ERR_CHANROLE_NEEDMOREPARAMS",
            .ERR_CHANROLE_INVALIDPARAMS => "ERR_CHANROLE_INVALIDPARAMS",
            .ERR_CHANROLE_NOSUCHROLE => "ERR_CHANROLE_NOSUCHROLE",
            .ERR_CHANROLE_TOOMANYPARAMS => "ERR_CHANROLE_TOOMANYPARAMS",
        };
    }
};

pub fn numericForError(err: Error) Numeric {
    return switch (err) {
        error.NeedMoreParams => .ERR_CHANROLE_NEEDMOREPARAMS,
        error.TooManyParams => .ERR_CHANROLE_TOOMANYPARAMS,
        error.NoSuchRole => .ERR_CHANROLE_NOSUCHROLE,
        else => .ERR_CHANROLE_INVALIDPARAMS,
    };
}

pub const CommandName = enum {
    chanrole,
    channel_role,

    pub fn token(self: CommandName) []const u8 {
        return switch (self) {
            .chanrole => "CHANROLE",
            .channel_role => "CHANNEL ROLE",
        };
    }
};

pub const Subcommand = enum {
    define,
    undefine,
    list,
    assign,
    unassign,
    resolve,

    pub fn parse(raw: []const u8) ?Subcommand {
        if (std.ascii.eqlIgnoreCase(raw, "DEFINE")) return .define;
        if (std.ascii.eqlIgnoreCase(raw, "DEF")) return .define;
        if (std.ascii.eqlIgnoreCase(raw, "UNDEFINE")) return .undefine;
        if (std.ascii.eqlIgnoreCase(raw, "UNDEF")) return .undefine;
        if (std.ascii.eqlIgnoreCase(raw, "DELETE")) return .undefine;
        if (std.ascii.eqlIgnoreCase(raw, "DEL")) return .undefine;
        if (std.ascii.eqlIgnoreCase(raw, "LIST")) return .list;
        if (std.ascii.eqlIgnoreCase(raw, "ASSIGN")) return .assign;
        if (std.ascii.eqlIgnoreCase(raw, "SET")) return .assign;
        if (std.ascii.eqlIgnoreCase(raw, "UNASSIGN")) return .unassign;
        if (std.ascii.eqlIgnoreCase(raw, "UNSET")) return .unassign;
        if (std.ascii.eqlIgnoreCase(raw, "RESOLVE")) return .resolve;
        if (std.ascii.eqlIgnoreCase(raw, "GET")) return .resolve;
        return null;
    }

    pub fn token(self: Subcommand) []const u8 {
        return switch (self) {
            .define => "DEFINE",
            .undefine => "UNDEFINE",
            .list => "LIST",
            .assign => "ASSIGN",
            .unassign => "UNASSIGN",
            .resolve => "RESOLVE",
        };
    }
};

pub const RoleFlag = enum(u5) {
    voice,
    halfop,
    op,
    admin,
    founder,
    invite,
    topic,
    kick,
    ban,
    mode,
    access,
    akick,
    metadata,
    guard,
    transfer,
};

pub const FlagSpec = struct {
    flag: RoleFlag,
    letter: u8,
    name: []const u8,
};

pub const flag_specs = [_]FlagSpec{
    .{ .flag = .voice, .letter = 'v', .name = "VOICE" },
    .{ .flag = .halfop, .letter = 'h', .name = "HALFOP" },
    .{ .flag = .op, .letter = 'o', .name = "OP" },
    .{ .flag = .admin, .letter = 'a', .name = "ADMIN" },
    .{ .flag = .founder, .letter = 'f', .name = "FOUNDER" },
    .{ .flag = .invite, .letter = 'i', .name = "INVITE" },
    .{ .flag = .topic, .letter = 't', .name = "TOPIC" },
    .{ .flag = .kick, .letter = 'k', .name = "KICK" },
    .{ .flag = .ban, .letter = 'b', .name = "BAN" },
    .{ .flag = .mode, .letter = 'm', .name = "MODE" },
    .{ .flag = .access, .letter = 'A', .name = "ACCESS" },
    .{ .flag = .akick, .letter = 'K', .name = "AKICK" },
    .{ .flag = .metadata, .letter = 'M', .name = "METADATA" },
    .{ .flag = .guard, .letter = 'g', .name = "GUARD" },
    .{ .flag = .transfer, .letter = 'x', .name = "TRANSFER" },
};

const render_specs = [_]FlagSpec{
    .{ .flag = .access, .letter = 'A', .name = "ACCESS" },
    .{ .flag = .akick, .letter = 'K', .name = "AKICK" },
    .{ .flag = .metadata, .letter = 'M', .name = "METADATA" },
    .{ .flag = .admin, .letter = 'a', .name = "ADMIN" },
    .{ .flag = .ban, .letter = 'b', .name = "BAN" },
    .{ .flag = .founder, .letter = 'f', .name = "FOUNDER" },
    .{ .flag = .guard, .letter = 'g', .name = "GUARD" },
    .{ .flag = .halfop, .letter = 'h', .name = "HALFOP" },
    .{ .flag = .invite, .letter = 'i', .name = "INVITE" },
    .{ .flag = .kick, .letter = 'k', .name = "KICK" },
    .{ .flag = .mode, .letter = 'm', .name = "MODE" },
    .{ .flag = .op, .letter = 'o', .name = "OP" },
    .{ .flag = .topic, .letter = 't', .name = "TOPIC" },
    .{ .flag = .voice, .letter = 'v', .name = "VOICE" },
    .{ .flag = .transfer, .letter = 'x', .name = "TRANSFER" },
};

comptime {
    if (flag_specs.len != @typeInfo(RoleFlag).@"enum".fields.len) {
        @compileError("missing role flag spec");
    }
    if (render_specs.len != flag_specs.len) {
        @compileError("missing role flag render spec");
    }
    for (flag_specs, 0..) |left, left_index| {
        for (flag_specs[left_index + 1 ..]) |right| {
            if (left.flag == right.flag) @compileError("duplicate role flag");
            if (left.letter == right.letter) @compileError("duplicate role flag letter");
            if (asciiEqlComptime(left.name, right.name)) @compileError("duplicate role flag name");
        }
    }
    for (render_specs, 0..) |left, left_index| {
        _ = specForFlag(left.flag) orelse @compileError("render spec references unknown role flag");
        for (render_specs[left_index + 1 ..]) |right| {
            if (left.letter > right.letter) @compileError("render specs must be sorted by letter");
        }
    }
}

pub const RoleFlags = packed struct(u32) {
    voice: bool = false,
    halfop: bool = false,
    op: bool = false,
    admin: bool = false,
    founder: bool = false,
    invite: bool = false,
    topic: bool = false,
    kick: bool = false,
    ban: bool = false,
    mode: bool = false,
    access: bool = false,
    akick: bool = false,
    metadata: bool = false,
    guard: bool = false,
    transfer: bool = false,
    reserved: u17 = 0,

    pub fn empty() RoleFlags {
        return .{};
    }

    pub fn one(flag: RoleFlag) RoleFlags {
        var out = RoleFlags.empty();
        out.set(flag);
        return out;
    }

    pub fn fromFlags(flags: []const RoleFlag) RoleFlags {
        var out = RoleFlags.empty();
        for (flags) |flag| out.set(flag);
        return out;
    }

    pub fn bits(self: RoleFlags) u32 {
        return @as(u32, @bitCast(self));
    }

    pub fn isEmpty(self: RoleFlags) bool {
        return self.bits() == 0;
    }

    pub fn eql(self: RoleFlags, other: RoleFlags) bool {
        return self.bits() == other.bits();
    }

    pub fn has(self: RoleFlags, flag: RoleFlag) bool {
        return switch (flag) {
            .voice => self.voice,
            .halfop => self.halfop,
            .op => self.op,
            .admin => self.admin,
            .founder => self.founder,
            .invite => self.invite,
            .topic => self.topic,
            .kick => self.kick,
            .ban => self.ban,
            .mode => self.mode,
            .access => self.access,
            .akick => self.akick,
            .metadata => self.metadata,
            .guard => self.guard,
            .transfer => self.transfer,
        };
    }

    pub fn set(self: *RoleFlags, flag: RoleFlag) void {
        switch (flag) {
            .voice => self.voice = true,
            .halfop => self.halfop = true,
            .op => self.op = true,
            .admin => self.admin = true,
            .founder => self.founder = true,
            .invite => self.invite = true,
            .topic => self.topic = true,
            .kick => self.kick = true,
            .ban => self.ban = true,
            .mode => self.mode = true,
            .access => self.access = true,
            .akick => self.akick = true,
            .metadata => self.metadata = true,
            .guard => self.guard = true,
            .transfer => self.transfer = true,
        }
    }

    pub fn clear(self: *RoleFlags, flag: RoleFlag) void {
        switch (flag) {
            .voice => self.voice = false,
            .halfop => self.halfop = false,
            .op => self.op = false,
            .admin => self.admin = false,
            .founder => self.founder = false,
            .invite => self.invite = false,
            .topic => self.topic = false,
            .kick => self.kick = false,
            .ban => self.ban = false,
            .mode => self.mode = false,
            .access => self.access = false,
            .akick => self.akick = false,
            .metadata => self.metadata = false,
            .guard => self.guard = false,
            .transfer => self.transfer = false,
        }
    }
};

pub fn flagFromLetter(letter: u8) ?RoleFlag {
    for (flag_specs) |spec| {
        if (spec.letter == letter) return spec.flag;
    }
    return null;
}

pub fn flagFromName(name: []const u8) ?RoleFlag {
    for (flag_specs) |spec| {
        if (std.ascii.eqlIgnoreCase(name, spec.name)) return spec.flag;
    }
    return null;
}

pub fn flagLetter(flag: RoleFlag) u8 {
    return specForFlag(flag).?.letter;
}

pub fn parseFlagSet(raw: []const u8) Error!RoleFlags {
    if (raw.len == 0) return error.EmptyFlagSet;
    if (raw.len > max_flag_expr_bytes) return error.FlagExpressionTooLong;
    if (std.mem.indexOfScalar(u8, raw, ',') != null) return parseNamedFlagSet(raw);

    var flags = RoleFlags.empty();
    var adding = true;
    var saw_flag = false;

    for (raw) |byte| {
        switch (byte) {
            '+' => adding = true,
            '-' => adding = false,
            ' ', '\t', '\r', '\n', 0 => return error.InvalidFlag,
            else => {
                const flag = flagFromLetter(byte) orelse return error.InvalidFlag;
                if (adding) {
                    flags.set(flag);
                    saw_flag = true;
                } else {
                    flags.clear(flag);
                }
            },
        }
    }

    if (!saw_flag or flags.isEmpty()) return error.EmptyFlagSet;
    return flags;
}

fn parseNamedFlagSet(raw: []const u8) Error!RoleFlags {
    var flags = RoleFlags.empty();
    var iter = std.mem.splitScalar(u8, raw, ',');
    var saw_flag = false;

    while (iter.next()) |part_raw| {
        const part = std.mem.trim(u8, part_raw, " \t");
        if (part.len == 0) return error.InvalidFlag;

        var adding = true;
        var name = part;
        if (name[0] == '+' or name[0] == '-') {
            adding = name[0] == '+';
            name = name[1..];
            if (name.len == 0) return error.InvalidFlag;
        }

        const flag = flagFromName(name) orelse return error.InvalidFlag;
        if (adding) {
            flags.set(flag);
            saw_flag = true;
        } else {
            flags.clear(flag);
        }
    }

    if (!saw_flag or flags.isEmpty()) return error.EmptyFlagSet;
    return flags;
}

pub fn renderFlags(flags: RoleFlags, out: []u8) Error![]const u8 {
    if (flags.isEmpty()) return error.EmptyFlagSet;
    if (out.len < 2) return error.OutputTooSmall;

    var pos: usize = 0;
    out[pos] = '+';
    pos += 1;

    for (render_specs) |spec| {
        if (!flags.has(spec.flag)) continue;
        if (pos >= out.len) return error.OutputTooSmall;
        out[pos] = spec.letter;
        pos += 1;
    }

    return out[0..pos];
}

pub const DefineRequest = struct {
    channel: []const u8,
    role: []const u8,
    flags: RoleFlags,
};

pub const RoleRef = struct {
    channel: []const u8,
    role: []const u8,
};

pub const ChannelRef = struct {
    channel: []const u8,
};

pub const AssignmentRequest = struct {
    channel: []const u8,
    account: []const u8,
    role: []const u8,
};

pub const AccountRef = struct {
    channel: []const u8,
    account: []const u8,
};

pub const Request = union(enum) {
    define: DefineRequest,
    undefine: RoleRef,
    list: ChannelRef,
    assign: AssignmentRequest,
    unassign: AccountRef,
    resolve: RoleRef,

    pub fn subcommand(self: Request) Subcommand {
        return switch (self) {
            .define => .define,
            .undefine => .undefine,
            .list => .list,
            .assign => .assign,
            .unassign => .unassign,
            .resolve => .resolve,
        };
    }
};

pub fn parse(args: []const []const u8) Error!Request {
    return parseWith(.{}, args);
}

pub fn parseWith(params: Params, args: []const []const u8) Error!Request {
    if (args.len == 0) return error.NeedMoreParams;
    for (args) |arg| try validateToken(params, arg);

    const subcommand_index: usize = blk: {
        if (std.ascii.eqlIgnoreCase(args[0], "CHANROLE")) break :blk 1;
        if (std.ascii.eqlIgnoreCase(args[0], "CHANNEL")) {
            if (args.len < 2) return error.NeedMoreParams;
            if (!std.ascii.eqlIgnoreCase(args[1], "ROLE")) return error.InvalidCommand;
            break :blk 2;
        }
        return error.InvalidCommand;
    };

    if (args.len <= subcommand_index) return error.NeedMoreParams;
    const subcommand = Subcommand.parse(args[subcommand_index]) orelse return error.InvalidSubcommand;
    const rest = args[subcommand_index + 1 ..];

    return switch (subcommand) {
        .define => blk: {
            if (rest.len < 3) return error.NeedMoreParams;
            if (rest.len > 3) return error.TooManyParams;
            try validateChannel(params, rest[0]);
            try validateRoleName(params, rest[1]);
            const flags = try parseFlagSet(rest[2]);
            break :blk Request{ .define = .{ .channel = rest[0], .role = rest[1], .flags = flags } };
        },
        .undefine => blk: {
            if (rest.len < 2) return error.NeedMoreParams;
            if (rest.len > 2) return error.TooManyParams;
            try validateChannel(params, rest[0]);
            try validateRoleName(params, rest[1]);
            break :blk Request{ .undefine = .{ .channel = rest[0], .role = rest[1] } };
        },
        .list => blk: {
            if (rest.len < 1) return error.NeedMoreParams;
            if (rest.len > 1) return error.TooManyParams;
            try validateChannel(params, rest[0]);
            break :blk Request{ .list = .{ .channel = rest[0] } };
        },
        .assign => blk: {
            if (rest.len < 3) return error.NeedMoreParams;
            if (rest.len > 3) return error.TooManyParams;
            try validateChannel(params, rest[0]);
            try validateAccount(params, rest[1]);
            try validateRoleName(params, rest[2]);
            break :blk Request{ .assign = .{ .channel = rest[0], .account = rest[1], .role = rest[2] } };
        },
        .unassign => blk: {
            if (rest.len < 2) return error.NeedMoreParams;
            if (rest.len > 2) return error.TooManyParams;
            try validateChannel(params, rest[0]);
            try validateAccount(params, rest[1]);
            break :blk Request{ .unassign = .{ .channel = rest[0], .account = rest[1] } };
        },
        .resolve => blk: {
            if (rest.len < 2) return error.NeedMoreParams;
            if (rest.len > 2) return error.TooManyParams;
            try validateChannel(params, rest[0]);
            try validateRoleName(params, rest[1]);
            break :blk Request{ .resolve = .{ .channel = rest[0], .role = rest[1] } };
        },
    };
}

pub const RoleEntry = struct {
    channel: []const u8,
    role: []const u8,
    flags: RoleFlags,
};

pub const RoleList = struct {
    allocator: std.mem.Allocator,
    items: []RoleEntry,

    pub fn deinit(self: *RoleList) void {
        self.allocator.free(self.items);
        self.* = undefined;
    }
};

pub const UndefineResult = struct {
    removed_role: bool,
    removed_assignments: usize,
};

pub const ChanRoleStore = struct {
    allocator: std.mem.Allocator,
    roles: std.StringHashMapUnmanaged(RoleFlags),
    assignments: std.StringHashMapUnmanaged([]u8),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .roles = .empty,
            .assignments = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        var role_it = self.roles.iterator();
        while (role_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.roles.deinit(self.allocator);

        var assignment_it = self.assignments.iterator();
        while (assignment_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.assignments.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn defineRole(self: *Self, channel: []const u8, role: []const u8, flags: RoleFlags) Error!void {
        try validateChannel(.{}, channel);
        try validateRoleName(.{}, role);
        if (flags.isEmpty()) return error.EmptyFlagSet;

        const key = try self.makeKey(channel, role);
        errdefer self.allocator.free(key);

        const gop = try self.roles.getOrPut(self.allocator, key);
        if (gop.found_existing) {
            self.allocator.free(key);
        }
        gop.value_ptr.* = flags;
    }

    pub fn undefineRole(self: *Self, channel: []const u8, role: []const u8) Error!UndefineResult {
        try validateChannel(.{}, channel);
        try validateRoleName(.{}, role);

        var result = UndefineResult{ .removed_role = false, .removed_assignments = 0 };
        const key = try self.makeKey(channel, role);
        defer self.allocator.free(key);

        if (self.roles.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            result.removed_role = true;
            result.removed_assignments = self.removeAssignmentsForRole(channel, role);
        }

        return result;
    }

    pub fn listRoles(self: *Self, allocator: std.mem.Allocator, channel: []const u8) Error!RoleList {
        try validateChannel(.{}, channel);
        const prefix = try self.makePrefix(channel);
        defer self.allocator.free(prefix);

        var count: usize = 0;
        var count_it = self.roles.iterator();
        while (count_it.next()) |entry| {
            if (std.mem.startsWith(u8, entry.key_ptr.*, prefix)) count += 1;
        }

        const items = try allocator.alloc(RoleEntry, count);
        errdefer allocator.free(items);

        var fill: usize = 0;
        var fill_it = self.roles.iterator();
        while (fill_it.next()) |entry| {
            if (!std.mem.startsWith(u8, entry.key_ptr.*, prefix)) continue;
            items[fill] = .{
                .channel = entry.key_ptr.*[0..channel.len],
                .role = entry.key_ptr.*[channel.len + 1 ..],
                .flags = entry.value_ptr.*,
            };
            fill += 1;
        }
        sortRoleEntries(items);

        return .{ .allocator = allocator, .items = items };
    }

    pub fn resolveRole(self: *Self, channel: []const u8, role: []const u8) ?RoleFlags {
        const key = self.makeKey(channel, role) catch return null;
        defer self.allocator.free(key);
        return self.roles.get(key);
    }

    pub fn assignRole(self: *Self, channel: []const u8, account: []const u8, role: []const u8) Error!void {
        try validateChannel(.{}, channel);
        try validateAccount(.{}, account);
        try validateRoleName(.{}, role);
        if (self.resolveRole(channel, role) == null) return error.NoSuchRole;

        const key = try self.makeKey(channel, account);
        errdefer self.allocator.free(key);

        const value = try self.allocator.dupe(u8, role);
        errdefer self.allocator.free(value);

        const gop = try self.assignments.getOrPut(self.allocator, key);
        if (gop.found_existing) {
            self.allocator.free(key);
            self.allocator.free(gop.value_ptr.*);
        }
        gop.value_ptr.* = value;
    }

    pub fn unassignRole(self: *Self, channel: []const u8, account: []const u8) Error!bool {
        try validateChannel(.{}, channel);
        try validateAccount(.{}, account);

        const key = try self.makeKey(channel, account);
        defer self.allocator.free(key);

        if (self.assignments.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
            return true;
        }
        return false;
    }

    pub fn assignedRole(self: *Self, channel: []const u8, account: []const u8) ?[]const u8 {
        const key = self.makeKey(channel, account) catch return null;
        defer self.allocator.free(key);
        return self.assignments.get(key);
    }

    pub fn resolveAccount(self: *Self, channel: []const u8, account: []const u8) ?RoleFlags {
        const role = self.assignedRole(channel, account) orelse return null;
        return self.resolveRole(channel, role);
    }

    pub fn clearChannel(self: *Self, channel: []const u8) Error!usize {
        try validateChannel(.{}, channel);
        const prefix = try self.makePrefix(channel);
        defer self.allocator.free(prefix);

        var removed: usize = 0;
        var role_keys = std.ArrayListUnmanaged([]const u8).empty;
        defer role_keys.deinit(self.allocator);
        var assignment_keys = std.ArrayListUnmanaged([]const u8).empty;
        defer assignment_keys.deinit(self.allocator);

        var role_it = self.roles.iterator();
        while (role_it.next()) |entry| {
            if (std.mem.startsWith(u8, entry.key_ptr.*, prefix)) {
                try role_keys.append(self.allocator, entry.key_ptr.*);
            }
        }

        var assignment_it = self.assignments.iterator();
        while (assignment_it.next()) |entry| {
            if (std.mem.startsWith(u8, entry.key_ptr.*, prefix)) {
                try assignment_keys.append(self.allocator, entry.key_ptr.*);
            }
        }

        for (role_keys.items) |key| {
            if (self.roles.fetchRemove(key)) |kv| {
                self.allocator.free(kv.key);
                removed += 1;
            }
        }

        for (assignment_keys.items) |key| {
            if (self.assignments.fetchRemove(key)) |kv| {
                self.allocator.free(kv.key);
                self.allocator.free(kv.value);
                removed += 1;
            }
        }

        return removed;
    }

    pub fn apply(self: *Self, request: Request) Error!?RoleFlags {
        return switch (request) {
            .define => |r| blk: {
                try self.defineRole(r.channel, r.role, r.flags);
                break :blk r.flags;
            },
            .undefine => |r| blk: {
                _ = try self.undefineRole(r.channel, r.role);
                break :blk null;
            },
            .list => null,
            .assign => |r| blk: {
                try self.assignRole(r.channel, r.account, r.role);
                break :blk self.resolveRole(r.channel, r.role);
            },
            .unassign => |r| blk: {
                _ = try self.unassignRole(r.channel, r.account);
                break :blk null;
            },
            .resolve => |r| self.resolveRole(r.channel, r.role),
        };
    }

    fn makeKey(self: *Self, channel: []const u8, name: []const u8) ![]u8 {
        const key = try self.allocator.alloc(u8, channel.len + 1 + name.len);
        for (channel, 0..) |byte, index| key[index] = std.ascii.toLower(byte);
        key[channel.len] = key_sep;
        for (name, 0..) |byte, index| key[channel.len + 1 + index] = std.ascii.toLower(byte);
        return key;
    }

    fn makePrefix(self: *Self, channel: []const u8) ![]u8 {
        const prefix = try self.allocator.alloc(u8, channel.len + 1);
        for (channel, 0..) |byte, index| prefix[index] = std.ascii.toLower(byte);
        prefix[channel.len] = key_sep;
        return prefix;
    }

    fn removeAssignmentsForRole(self: *Self, channel: []const u8, role: []const u8) usize {
        const prefix = self.makePrefix(channel) catch return 0;
        defer self.allocator.free(prefix);

        var removed: usize = 0;
        var keys = std.ArrayListUnmanaged([]const u8).empty;
        defer keys.deinit(self.allocator);

        var it = self.assignments.iterator();
        while (it.next()) |entry| {
            if (std.mem.startsWith(u8, entry.key_ptr.*, prefix) and std.ascii.eqlIgnoreCase(entry.value_ptr.*, role)) {
                keys.append(self.allocator, entry.key_ptr.*) catch return 0;
            }
        }

        for (keys.items) |key| {
            if (self.assignments.fetchRemove(key)) |kv| {
                self.allocator.free(kv.key);
                self.allocator.free(kv.value);
                removed += 1;
            }
        }
        return removed;
    }
};

fn validateToken(params: Params, token: []const u8) Error!void {
    if (token.len == 0) return error.EmptyToken;
    if (token.len > params.max_token_bytes) return error.TokenTooLong;
    if (containsByte(token, 0) or containsByte(token, '\r') or containsByte(token, '\n')) return error.EmptyToken;
}

fn validateChannel(params: Params, channel: []const u8) Error!void {
    if (channel.len == 0) return error.InvalidChannel;
    if (channel.len > params.max_channel_bytes) return error.ChannelTooLong;
    if (channel[0] != '#' and channel[0] != '&') return error.InvalidChannel;
    for (channel) |byte| {
        switch (byte) {
            0, ' ', ',', '\r', '\n' => return error.InvalidChannel,
            else => {},
        }
    }
}

fn validateAccount(params: Params, account: []const u8) Error!void {
    if (account.len == 0) return error.InvalidAccount;
    if (account.len > params.max_account_bytes) return error.AccountTooLong;
    for (account) |byte| {
        switch (byte) {
            0, ' ', ',', '\r', '\n', '#', '&' => return error.InvalidAccount,
            else => {},
        }
    }
}

fn validateRoleName(params: Params, role: []const u8) Error!void {
    if (role.len == 0) return error.InvalidRoleName;
    if (role.len > params.max_role_bytes) return error.RoleNameTooLong;
    if (!std.ascii.isAlphanumeric(role[0])) return error.InvalidRoleName;
    for (role) |byte| {
        if (std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '-') continue;
        return error.InvalidRoleName;
    }
    if (isReservedXopRole(role)) return error.ReservedRoleName;
}

fn isReservedXopRole(role: []const u8) bool {
    const reserved = [_][]const u8{
        "VOICE",
        "HOP",
        "HALFOP",
        "OP",
        "AOP",
        "SOP",
        "QOP",
        "ADMIN",
        "OWNER",
        "FOUNDER",
        "AKICK",
        "VOP",
    };
    for (reserved) |name| {
        if (std.ascii.eqlIgnoreCase(role, name)) return true;
    }
    return false;
}

fn containsByte(haystack: []const u8, needle: u8) bool {
    return std.mem.indexOfScalar(u8, haystack, needle) != null;
}

fn specForFlag(flag: RoleFlag) ?FlagSpec {
    for (flag_specs) |spec| {
        if (spec.flag == flag) return spec;
    }
    return null;
}

fn asciiEqlComptime(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toUpper(x) != std.ascii.toUpper(y)) return false;
    }
    return true;
}

fn sortRoleEntries(items: []RoleEntry) void {
    var i: usize = 1;
    while (i < items.len) : (i += 1) {
        const item = items[i];
        var j = i;
        while (j > 0 and std.mem.lessThan(u8, item.role, items[j - 1].role)) : (j -= 1) {
            items[j] = items[j - 1];
        }
        items[j] = item;
    }
}

test "flag parser accepts mode letters and renders stable numeric-safe flags" {
    const flags = try parseFlagSet("+ovkA");
    try std.testing.expect(flags.has(.op));
    try std.testing.expect(flags.has(.voice));
    try std.testing.expect(flags.has(.kick));
    try std.testing.expect(flags.has(.access));
    try std.testing.expect(!flags.has(.ban));

    var rendered_buf: [16]u8 = undefined;
    const rendered = try renderFlags(flags, &rendered_buf);
    try std.testing.expectEqualStrings("+Akov", rendered);

    const without_voice = try parseFlagSet("+ov-v");
    try std.testing.expect(without_voice.has(.op));
    try std.testing.expect(!without_voice.has(.voice));
}

test "flag parser accepts named comma lists case-insensitively" {
    const flags = try parseFlagSet("voice,OP,+kick,-voice,metadata");
    try std.testing.expect(!flags.has(.voice));
    try std.testing.expect(flags.has(.op));
    try std.testing.expect(flags.has(.kick));
    try std.testing.expect(flags.has(.metadata));

    try std.testing.expectError(error.InvalidFlag, parseFlagSet("op,unknown"));
    try std.testing.expectError(error.EmptyFlagSet, parseFlagSet("+o-o"));
    try std.testing.expectError(error.InvalidFlag, parseFlagSet("+o\n"));
}

test "parse real CHANROLE commands without service-user routing" {
    const define_args = [_][]const u8{ "CHANROLE", "DEFINE", "#ops", "moderator", "+ovk" };
    const define = try parse(&define_args);
    try std.testing.expectEqual(Subcommand.define, define.subcommand());
    try std.testing.expectEqualStrings("#ops", define.define.channel);
    try std.testing.expectEqualStrings("moderator", define.define.role);
    try std.testing.expect(define.define.flags.has(.voice));
    try std.testing.expect(define.define.flags.has(.op));
    try std.testing.expect(define.define.flags.has(.kick));

    const channel_role_args = [_][]const u8{ "CHANNEL", "ROLE", "ASSIGN", "#ops", "alice", "moderator" };
    const assign = try parse(&channel_role_args);
    try std.testing.expectEqual(Subcommand.assign, assign.subcommand());
    try std.testing.expectEqualStrings("alice", assign.assign.account);
    try std.testing.expectEqualStrings("moderator", assign.assign.role);

    const bogus_command_args = [_][]const u8{ "BOGUSROLE", "DEFINE", "#ops", "moderator", "+o" };
    try std.testing.expectError(error.InvalidCommand, parse(&bogus_command_args));
}

test "parse validates arity names channels accounts and limits" {
    const missing = [_][]const u8{ "CHANROLE", "DEFINE", "#ops" };
    try std.testing.expectError(error.NeedMoreParams, parse(&missing));

    const too_many = [_][]const u8{ "CHANROLE", "LIST", "#ops", "extra" };
    try std.testing.expectError(error.TooManyParams, parse(&too_many));

    const bad_channel = [_][]const u8{ "CHANROLE", "LIST", "ops" };
    try std.testing.expectError(error.InvalidChannel, parse(&bad_channel));

    const reserved = [_][]const u8{ "CHANROLE", "DEFINE", "#ops", "AOP", "+o" };
    try std.testing.expectError(error.ReservedRoleName, parse(&reserved));

    const bad_account = [_][]const u8{ "CHANROLE", "ASSIGN", "#ops", "#not-account", "moderator" };
    try std.testing.expectError(error.InvalidAccount, parse(&bad_account));

    const long_role = [_][]const u8{ "CHANROLE", "DEFINE", "#ops", "x" ** (max_role_bytes + 1), "+o" };
    try std.testing.expectError(error.RoleNameTooLong, parse(&long_role));
}

test "store defines overwrites resolves and lists roles per channel" {
    const allocator = std.testing.allocator;
    var store = ChanRoleStore.init(allocator);
    defer store.deinit();

    const mod_flags = RoleFlags.fromFlags(&.{ .voice, .op, .kick });
    const curator_flags = RoleFlags.fromFlags(&.{ .voice, .topic, .metadata });
    try store.defineRole("#ops", "moderator", mod_flags);
    try store.defineRole("#ops", "curator", curator_flags);
    try store.defineRole("#other", "moderator", RoleFlags.one(.voice));

    try std.testing.expect(store.resolveRole("#ops", "moderator").?.eql(mod_flags));
    try std.testing.expect(store.resolveRole("#ops", "curator").?.eql(curator_flags));
    try std.testing.expect(store.resolveRole("#missing", "moderator") == null);

    const updated = RoleFlags.fromFlags(&.{ .voice, .op, .ban, .mode });
    try store.defineRole("#ops", "moderator", updated);
    try std.testing.expect(store.resolveRole("#ops", "moderator").?.eql(updated));

    var list = try store.listRoles(allocator, "#ops");
    defer list.deinit();
    try std.testing.expectEqual(@as(usize, 2), list.items.len);
    try std.testing.expectEqualStrings("curator", list.items[0].role);
    try std.testing.expectEqualStrings("moderator", list.items[1].role);
    try std.testing.expect(list.items[1].flags.has(.ban));
}

test "store assigns accounts to roles and resolves through current role definition" {
    const allocator = std.testing.allocator;
    var store = ChanRoleStore.init(allocator);
    defer store.deinit();

    try store.defineRole("#ops", "moderator", RoleFlags.fromFlags(&.{ .op, .kick }));
    try store.assignRole("#ops", "alice", "moderator");

    try std.testing.expectEqualStrings("moderator", store.assignedRole("#ops", "alice").?);
    try std.testing.expect(store.resolveAccount("#ops", "alice").?.has(.op));
    try std.testing.expect(store.resolveAccount("#ops", "alice").?.has(.kick));
    try std.testing.expect(!store.resolveAccount("#ops", "alice").?.has(.ban));

    try store.defineRole("#ops", "moderator", RoleFlags.fromFlags(&.{ .op, .ban }));
    try std.testing.expect(store.resolveAccount("#ops", "alice").?.has(.ban));
    try std.testing.expect(!store.resolveAccount("#ops", "alice").?.has(.kick));

    try std.testing.expectError(error.NoSuchRole, store.assignRole("#ops", "bob", "missing"));
}

test "assignment overwrite unassign and channel isolation" {
    const allocator = std.testing.allocator;
    var store = ChanRoleStore.init(allocator);
    defer store.deinit();

    try store.defineRole("#ops", "moderator", RoleFlags.one(.op));
    try store.defineRole("#ops", "curator", RoleFlags.one(.topic));
    try store.defineRole("#other", "moderator", RoleFlags.one(.voice));

    try store.assignRole("#ops", "alice", "moderator");
    try store.assignRole("#other", "alice", "moderator");
    try store.assignRole("#ops", "alice", "curator");

    try std.testing.expectEqualStrings("curator", store.assignedRole("#ops", "alice").?);
    try std.testing.expect(store.resolveAccount("#ops", "alice").?.has(.topic));
    try std.testing.expect(store.resolveAccount("#other", "alice").?.has(.voice));

    try std.testing.expect(try store.unassignRole("#ops", "alice"));
    try std.testing.expect(store.assignedRole("#ops", "alice") == null);
    try std.testing.expect(!try store.unassignRole("#ops", "alice"));
    try std.testing.expectEqualStrings("moderator", store.assignedRole("#other", "alice").?);
}

test "undefine removes only assignments that point at the removed channel role" {
    const allocator = std.testing.allocator;
    var store = ChanRoleStore.init(allocator);
    defer store.deinit();

    try store.defineRole("#ops", "moderator", RoleFlags.one(.op));
    try store.defineRole("#ops", "curator", RoleFlags.one(.topic));
    try store.defineRole("#other", "moderator", RoleFlags.one(.voice));
    try store.assignRole("#ops", "alice", "moderator");
    try store.assignRole("#ops", "bob", "curator");
    try store.assignRole("#other", "alice", "moderator");

    const removed = try store.undefineRole("#ops", "moderator");
    try std.testing.expect(removed.removed_role);
    try std.testing.expectEqual(@as(usize, 1), removed.removed_assignments);
    try std.testing.expect(store.resolveRole("#ops", "moderator") == null);
    try std.testing.expect(store.assignedRole("#ops", "alice") == null);
    try std.testing.expectEqualStrings("curator", store.assignedRole("#ops", "bob").?);
    try std.testing.expectEqualStrings("moderator", store.assignedRole("#other", "alice").?);

    const absent = try store.undefineRole("#ops", "moderator");
    try std.testing.expect(!absent.removed_role);
    try std.testing.expectEqual(@as(usize, 0), absent.removed_assignments);
}

test "clearChannel removes role definitions and assignments for one channel only" {
    const allocator = std.testing.allocator;
    var store = ChanRoleStore.init(allocator);
    defer store.deinit();

    try store.defineRole("#ops", "moderator", RoleFlags.one(.op));
    try store.defineRole("#ops", "curator", RoleFlags.one(.topic));
    try store.defineRole("#ops-extra", "moderator", RoleFlags.one(.voice));
    try store.assignRole("#ops", "alice", "moderator");
    try store.assignRole("#ops-extra", "alice", "moderator");

    try std.testing.expectEqual(@as(usize, 3), try store.clearChannel("#ops"));
    try std.testing.expect(store.resolveRole("#ops", "moderator") == null);
    try std.testing.expect(store.assignedRole("#ops", "alice") == null);
    try std.testing.expect(store.resolveRole("#ops-extra", "moderator").?.has(.voice));
    try std.testing.expectEqualStrings("moderator", store.assignedRole("#ops-extra", "alice").?);
}

test "apply executes parsed mutating requests" {
    const allocator = std.testing.allocator;
    var store = ChanRoleStore.init(allocator);
    defer store.deinit();

    const define_args = [_][]const u8{ "CHANROLE", "DEFINE", "#ops", "moderator", "+ok" };
    const assign_args = [_][]const u8{ "CHANNEL", "ROLE", "ASSIGN", "#ops", "alice", "moderator" };
    const resolve_args = [_][]const u8{ "CHANROLE", "RESOLVE", "#ops", "moderator" };

    const defined = (try store.apply(try parse(&define_args))).?;
    try std.testing.expect(defined.has(.op));
    try std.testing.expect(defined.has(.kick));

    const assigned = (try store.apply(try parse(&assign_args))).?;
    try std.testing.expect(assigned.has(.op));
    try std.testing.expect(store.resolveAccount("#ops", "alice").?.has(.kick));

    const resolved = (try store.apply(try parse(&resolve_args))).?;
    try std.testing.expect(resolved.has(.op));
}

test "numeric mapping keeps replies on server numerics" {
    try std.testing.expectEqual(@as(u16, 740), Numeric.RPL_CHANROLE.code());
    try std.testing.expectEqual(@as(u16, 942), Numeric.ERR_CHANROLE_NOSUCHROLE.code());
    try std.testing.expectEqualStrings("ERR_CHANROLE_NOSUCHROLE", Numeric.ERR_CHANROLE_NOSUCHROLE.token());
    try std.testing.expectEqual(Numeric.ERR_CHANROLE_NEEDMOREPARAMS, numericForError(error.NeedMoreParams));
    try std.testing.expectEqual(Numeric.ERR_CHANROLE_TOOMANYPARAMS, numericForError(error.TooManyParams));
    try std.testing.expectEqual(Numeric.ERR_CHANROLE_NOSUCHROLE, numericForError(error.NoSuchRole));
    try std.testing.expectEqual(Numeric.ERR_CHANROLE_INVALIDPARAMS, numericForError(error.InvalidRoleName));
}
