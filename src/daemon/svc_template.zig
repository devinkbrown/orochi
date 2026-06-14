//! Standalone services role-template store for Orochi.
//!
//! Services remain real server commands and numerics: this module models a
//! `SVCTEMPLATE` command surface and intentionally contains no pseudo-client
//! aliases. It imports only `std`, owns every key string it stores, and keeps
//! parsing/state logic pure for direct testing.

const std = @import("std");

pub const command_name = "SVCTEMPLATE";
pub const default_max_templates: usize = 256;
pub const max_channel_len: usize = 64;
pub const max_role_len: usize = 32;

const key_sep: u8 = 0;

/// Numeric slots reserved for server-command integrations. The exact line
/// renderer belongs in daemon dispatch, not in this standalone data module.
pub const Numeric = enum(u16) {
    rpl_svctemplate = 760,
    rpl_svctemplateend = 761,
    err_svctemplate = 762,
};

pub const TemplateError = std.mem.Allocator.Error || error{
    UnknownCommand,
    UnknownSubcommand,
    MissingParameter,
    TrailingParameter,
    InvalidChannel,
    InvalidRole,
    InvalidFlag,
    MissingFlagOperation,
    EmptyFlagSet,
    TooManyTemplates,
    BufferTooSmall,
};

pub const ChannelFlag = enum(u6) {
    invite_only,
    moderated,
    no_external,
    topic_ops,
    secret,
    no_ctcp,
    no_notice,
    no_nick,
    free_invite,
    tls_only,
    mod_reg,
    private,
    hidden,
    authonly,
    noformat,
    cloneable,
    registered,
    service,
    auditorium,
    nowhisper,
    nocomicdata,
    opmoderate,
    freetarget,
    disforward,
};

pub const FlagSpec = struct {
    flag: ChannelFlag,
    letter: u8,
    name: []const u8,
};

pub const flag_specs = [_]FlagSpec{
    .{ .flag = .invite_only, .letter = 'i', .name = "INVITEONLY" },
    .{ .flag = .moderated, .letter = 'm', .name = "MODERATED" },
    .{ .flag = .no_external, .letter = 'n', .name = "NOEXTERNAL" },
    .{ .flag = .topic_ops, .letter = 't', .name = "TOPICOPS" },
    .{ .flag = .secret, .letter = 's', .name = "SECRET" },
    .{ .flag = .no_ctcp, .letter = 'C', .name = "NOCTCP" },
    .{ .flag = .no_notice, .letter = 'T', .name = "NONOTICE" },
    .{ .flag = .no_nick, .letter = 'N', .name = "NONICK" },
    .{ .flag = .free_invite, .letter = 'g', .name = "FREEINVITE" },
    .{ .flag = .tls_only, .letter = 'S', .name = "TLSONLY" },
    .{ .flag = .mod_reg, .letter = 'M', .name = "MODREG" },
    .{ .flag = .private, .letter = 'p', .name = "PRIVATE" },
    .{ .flag = .hidden, .letter = 'h', .name = "HIDDEN" },
    .{ .flag = .authonly, .letter = 'a', .name = "AUTHONLY" },
    .{ .flag = .noformat, .letter = 'f', .name = "NOFORMAT" },
    .{ .flag = .cloneable, .letter = 'd', .name = "CLONEABLE" },
    .{ .flag = .registered, .letter = 'r', .name = "REGISTERED" },
    .{ .flag = .service, .letter = 'z', .name = "SERVICE" },
    .{ .flag = .auditorium, .letter = 'x', .name = "AUDITORIUM" },
    .{ .flag = .nowhisper, .letter = 'w', .name = "NOWHISPER" },
    .{ .flag = .nocomicdata, .letter = 'V', .name = "NOCOMICDATA" },
    .{ .flag = .opmoderate, .letter = 'O', .name = "OPMODERATE" },
    .{ .flag = .freetarget, .letter = 'F', .name = "FREETARGET" },
    .{ .flag = .disforward, .letter = 'D', .name = "DISFORWARD" },
};

pub const FlagSet = struct {
    bits: u64 = 0,

    pub fn empty() FlagSet {
        return .{};
    }

    pub fn one(flag: ChannelFlag) FlagSet {
        var out = FlagSet.empty();
        out.set(flag);
        return out;
    }

    pub fn fromFlags(flags: []const ChannelFlag) FlagSet {
        var out = FlagSet.empty();
        for (flags) |flag| out.set(flag);
        return out;
    }

    pub fn set(self: *FlagSet, flag: ChannelFlag) void {
        self.bits |= flagBit(flag);
    }

    pub fn clear(self: *FlagSet, flag: ChannelFlag) void {
        self.bits &= ~flagBit(flag);
    }

    pub fn has(self: FlagSet, flag: ChannelFlag) bool {
        return (self.bits & flagBit(flag)) != 0;
    }

    pub fn eql(self: FlagSet, other: FlagSet) bool {
        return self.bits == other.bits;
    }

    pub fn isEmpty(self: FlagSet) bool {
        return self.bits == 0;
    }
};

pub const DefineArgs = struct {
    channel: []const u8,
    role: []const u8,
    flags: FlagSet,
};

pub const LookupArgs = struct {
    channel: []const u8,
    role: []const u8,
};

pub const ListArgs = struct {
    channel: []const u8,
};

pub const Command = union(enum) {
    define: DefineArgs,
    undefine: LookupArgs,
    list: ListArgs,
    resolve: LookupArgs,
};

pub const TemplateEntry = struct {
    role: []const u8,
    flags: FlagSet,
};

pub const ApplyResult = union(enum) {
    defined: bool,
    undefined: bool,
    listed: []const TemplateEntry,
    resolved: ?FlagSet,
};

pub const TemplateStore = struct {
    allocator: std.mem.Allocator,
    table: std.StringHashMapUnmanaged(FlagSet),
    max_templates: usize,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return initBounded(allocator, default_max_templates);
    }

    pub fn initBounded(allocator: std.mem.Allocator, max_templates: usize) Self {
        return .{
            .allocator = allocator,
            .table = .empty,
            .max_templates = max_templates,
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.table.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.table.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn count(self: *const Self) usize {
        return self.table.count();
    }

    pub fn define(self: *Self, channel: []const u8, role: []const u8, flags: FlagSet) TemplateError!bool {
        try validateChannel(channel);
        try validateRole(role);

        const key = try self.makeKey(channel, role);
        errdefer self.allocator.free(key);

        const gop = try self.table.getOrPut(self.allocator, key);
        if (gop.found_existing) {
            self.allocator.free(key);
            gop.value_ptr.* = flags;
            return false;
        }

        if (self.table.count() > self.max_templates) {
            _ = self.table.remove(key);
            return error.TooManyTemplates;
        }

        gop.value_ptr.* = flags;
        return true;
    }

    pub fn undefine(self: *Self, channel: []const u8, role: []const u8) bool {
        const probe = self.makeProbe(channel, role) catch return false;
        defer probe.deinit(self.allocator);

        if (self.table.fetchRemove(probe.bytes)) |kv| {
            self.allocator.free(kv.key);
            return true;
        }
        return false;
    }

    pub fn resolve(self: *Self, channel: []const u8, role: []const u8) ?FlagSet {
        const probe = self.makeProbe(channel, role) catch return null;
        defer probe.deinit(self.allocator);
        return self.table.get(probe.bytes);
    }

    pub fn list(self: *Self, channel: []const u8, out: []TemplateEntry) TemplateError![]const TemplateEntry {
        try validateChannel(channel);

        var needed: usize = 0;
        var it_count = self.table.iterator();
        while (it_count.next()) |entry| {
            if (keyChannelEql(entry.key_ptr.*, channel)) needed += 1;
        }
        if (out.len < needed) return error.BufferTooSmall;

        var written: usize = 0;
        var it = self.table.iterator();
        while (it.next()) |entry| {
            if (!keyChannelEql(entry.key_ptr.*, channel)) continue;
            out[written] = .{
                .role = keyRole(entry.key_ptr.*),
                .flags = entry.value_ptr.*,
            };
            written += 1;
        }
        return out[0..written];
    }

    pub fn clearChannel(self: *Self, channel: []const u8) usize {
        const prefix = self.makePrefix(channel) catch return 0;
        defer prefix.deinit(self.allocator);

        var removed: usize = 0;
        var it = self.table.iterator();
        while (it.next()) |entry| {
            if (std.mem.startsWith(u8, entry.key_ptr.*, prefix.bytes)) {
                const key = entry.key_ptr.*;
                self.table.removeByPtr(entry.key_ptr);
                self.allocator.free(key);
                removed += 1;
            }
        }
        return removed;
    }

    pub fn apply(self: *Self, command: Command, list_out: []TemplateEntry) TemplateError!ApplyResult {
        return switch (command) {
            .define => |args| .{ .defined = try self.define(args.channel, args.role, args.flags) },
            .undefine => |args| .{ .undefined = self.undefine(args.channel, args.role) },
            .list => |args| .{ .listed = try self.list(args.channel, list_out) },
            .resolve => |args| .{ .resolved = self.resolve(args.channel, args.role) },
        };
    }

    fn makeKey(self: *Self, channel: []const u8, role: []const u8) ![]u8 {
        const key = try self.allocator.alloc(u8, channel.len + 1 + role.len);
        @memcpy(key[0..channel.len], channel);
        key[channel.len] = key_sep;
        @memcpy(key[channel.len + 1 ..], role);
        return key;
    }

    fn makeProbe(self: *Self, channel: []const u8, role: []const u8) !Probe {
        try validateChannel(channel);
        try validateRole(role);
        return Probe.init(self.allocator, channel, role);
    }

    fn makePrefix(self: *Self, channel: []const u8) !Probe {
        try validateChannel(channel);
        return Probe.initPrefix(self.allocator, channel);
    }
};

const Probe = struct {
    bytes: []const u8,
    heap: ?[]u8 = null,

    fn init(allocator: std.mem.Allocator, channel: []const u8, role: []const u8) !Probe {
        const bytes = try allocator.alloc(u8, channel.len + 1 + role.len);
        @memcpy(bytes[0..channel.len], channel);
        bytes[channel.len] = key_sep;
        @memcpy(bytes[channel.len + 1 ..], role);
        return .{ .bytes = bytes, .heap = bytes };
    }

    fn initPrefix(allocator: std.mem.Allocator, channel: []const u8) !Probe {
        const bytes = try allocator.alloc(u8, channel.len + 1);
        @memcpy(bytes[0..channel.len], channel);
        bytes[channel.len] = key_sep;
        return .{ .bytes = bytes, .heap = bytes };
    }

    fn deinit(self: Probe, allocator: std.mem.Allocator) void {
        if (self.heap) |bytes| allocator.free(bytes);
    }
};

pub fn parseCommand(line: []const u8) TemplateError!Command {
    var rest = trim(line);
    const verb = nextToken(&rest) orelse return error.MissingParameter;
    if (!asciiEql(verb, command_name)) return error.UnknownCommand;

    const subcommand = nextToken(&rest) orelse return error.MissingParameter;
    if (asciiEql(subcommand, "DEFINE")) {
        const channel = nextToken(&rest) orelse return error.MissingParameter;
        const role = nextToken(&rest) orelse return error.MissingParameter;
        const flags_text = trim(rest);
        if (flags_text.len == 0) return error.MissingParameter;
        try validateChannel(channel);
        try validateRole(role);
        return .{ .define = .{
            .channel = channel,
            .role = role,
            .flags = try parseFlagSet(flags_text),
        } };
    }
    if (asciiEql(subcommand, "UNDEFINE") or asciiEql(subcommand, "UNDEF")) {
        const channel = nextToken(&rest) orelse return error.MissingParameter;
        const role = nextToken(&rest) orelse return error.MissingParameter;
        if (nextToken(&rest) != null) return error.TrailingParameter;
        try validateChannel(channel);
        try validateRole(role);
        return .{ .undefine = .{ .channel = channel, .role = role } };
    }
    if (asciiEql(subcommand, "LIST")) {
        const channel = nextToken(&rest) orelse return error.MissingParameter;
        if (nextToken(&rest) != null) return error.TrailingParameter;
        try validateChannel(channel);
        return .{ .list = .{ .channel = channel } };
    }
    if (asciiEql(subcommand, "RESOLVE")) {
        const channel = nextToken(&rest) orelse return error.MissingParameter;
        const role = nextToken(&rest) orelse return error.MissingParameter;
        if (nextToken(&rest) != null) return error.TrailingParameter;
        try validateChannel(channel);
        try validateRole(role);
        return .{ .resolve = .{ .channel = channel, .role = role } };
    }
    return error.UnknownSubcommand;
}

pub fn parseFlagSet(text: []const u8) TemplateError!FlagSet {
    const input = trim(text);
    if (input.len == 0) return error.EmptyFlagSet;
    if (asciiEql(input, "NONE") or std.mem.eql(u8, input, "0")) return FlagSet.empty();

    if (input[0] == '+' or input[0] == '-') return parseModeLetters(input);

    var out = FlagSet.empty();
    var any = false;
    var it = std.mem.splitScalar(u8, input, ',');
    while (it.next()) |raw_part| {
        const part = trim(raw_part);
        if (part.len == 0) return error.InvalidFlag;
        const flag = nameToFlag(part) orelse return error.InvalidFlag;
        out.set(flag);
        any = true;
    }
    if (!any) return error.EmptyFlagSet;
    return out;
}

pub fn renderFlagLetters(flags: FlagSet, out: []u8) TemplateError![]const u8 {
    var needed: usize = 1;
    for (flag_specs) |spec| {
        if (flags.has(spec.flag)) needed += 1;
    }
    if (needed == 1) return out[0..0];
    if (out.len < needed) return error.BufferTooSmall;

    out[0] = '+';
    var len: usize = 1;
    for (flag_specs) |spec| {
        if (!flags.has(spec.flag)) continue;
        out[len] = spec.letter;
        len += 1;
    }
    return out[0..len];
}

pub fn letterToFlag(letter: u8) ?ChannelFlag {
    for (flag_specs) |spec| {
        if (spec.letter == letter) return spec.flag;
    }
    return null;
}

pub fn nameToFlag(name: []const u8) ?ChannelFlag {
    for (flag_specs) |spec| {
        if (asciiEql(name, spec.name)) return spec.flag;
        if (asciiNameEql(name, spec.name)) return spec.flag;
    }
    return null;
}

pub fn validateChannel(channel: []const u8) TemplateError!void {
    if (channel.len == 0 or channel.len > max_channel_len) return error.InvalidChannel;
    if (channel[0] != '#' and channel[0] != '&') return error.InvalidChannel;
    for (channel) |byte| {
        if (byte == key_sep or isSpace(byte) or byte == ',') return error.InvalidChannel;
    }
}

pub fn validateRole(role: []const u8) TemplateError!void {
    if (role.len == 0 or role.len > max_role_len) return error.InvalidRole;
    for (role) |byte| {
        if (!isRoleByte(byte)) return error.InvalidRole;
    }
}

fn parseModeLetters(input: []const u8) TemplateError!FlagSet {
    var flags = FlagSet.empty();
    var op: ?enum { add, remove } = null;
    var any = false;

    for (input) |byte| {
        switch (byte) {
            '+' => op = .add,
            '-' => op = .remove,
            else => {
                const active = op orelse return error.MissingFlagOperation;
                const flag = letterToFlag(byte) orelse return error.InvalidFlag;
                switch (active) {
                    .add => flags.set(flag),
                    .remove => flags.clear(flag),
                }
                any = true;
            },
        }
    }
    if (!any) return error.EmptyFlagSet;
    return flags;
}

fn nextToken(rest: *[]const u8) ?[]const u8 {
    var input = trim(rest.*);
    if (input.len == 0) {
        rest.* = input;
        return null;
    }

    var end: usize = 0;
    while (end < input.len and !isSpace(input[end])) : (end += 1) {}
    const token = input[0..end];
    rest.* = input[end..];
    return token;
}

fn trim(bytes: []const u8) []const u8 {
    return std.mem.trim(u8, bytes, " \t\r\n");
}

fn flagBit(flag: ChannelFlag) u64 {
    return @as(u64, 1) << @as(u6, @intCast(@intFromEnum(flag)));
}

fn keyChannelEql(key: []const u8, channel: []const u8) bool {
    if (key.len <= channel.len) return false;
    return key[channel.len] == key_sep and std.mem.eql(u8, key[0..channel.len], channel);
}

fn keyRole(key: []const u8) []const u8 {
    const sep = std.mem.indexOfScalar(u8, key, key_sep).?;
    return key[sep + 1 ..];
}

fn asciiEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (asciiLower(left) != asciiLower(right)) return false;
    }
    return true;
}

fn asciiNameEql(a: []const u8, b: []const u8) bool {
    var ai: usize = 0;
    var bi: usize = 0;
    while (true) {
        while (ai < a.len and (a[ai] == '_' or a[ai] == '-')) : (ai += 1) {}
        while (bi < b.len and (b[bi] == '_' or b[bi] == '-')) : (bi += 1) {}
        if (ai == a.len or bi == b.len) return ai == a.len and bi == b.len;
        if (asciiLower(a[ai]) != asciiLower(b[bi])) return false;
        ai += 1;
        bi += 1;
    }
}

fn asciiLower(byte: u8) u8 {
    return if (byte >= 'A' and byte <= 'Z') byte + ('a' - 'A') else byte;
}

fn isSpace(byte: u8) bool {
    return byte == ' ' or byte == '\t' or byte == '\r' or byte == '\n';
}

fn isRoleByte(byte: u8) bool {
    return (byte >= 'A' and byte <= 'Z') or
        (byte >= 'a' and byte <= 'z') or
        (byte >= '0' and byte <= '9') or
        byte == '_' or byte == '-' or byte == '.';
}

test "parse SVCTEMPLATE commands and reject non-server aliases" {
    try std.testing.expectError(error.UnknownCommand, parseCommand("TEMPLATE DEFINE #ops founder +mnt"));
    try std.testing.expectError(error.UnknownCommand, parseCommand("SERVICE TEMPLATE DEFINE #ops founder +mnt"));

    const parsed = try parseCommand("SVCTEMPLATE DEFINE #ops founder +mntS");
    switch (parsed) {
        .define => |args| {
            try std.testing.expectEqualStrings("#ops", args.channel);
            try std.testing.expectEqualStrings("founder", args.role);
            try std.testing.expect(args.flags.has(.moderated));
            try std.testing.expect(args.flags.has(.no_external));
            try std.testing.expect(args.flags.has(.topic_ops));
            try std.testing.expect(args.flags.has(.tls_only));
            try std.testing.expect(!args.flags.has(.secret));
        },
        else => return error.TestUnexpectedResult,
    }

    const undef = try parseCommand("  svctemplate   undef   #ops   founder  ");
    switch (undef) {
        .undefine => |args| {
            try std.testing.expectEqualStrings("#ops", args.channel);
            try std.testing.expectEqualStrings("founder", args.role);
        },
        else => return error.TestUnexpectedResult,
    }

    const listed = try parseCommand("SVCTEMPLATE LIST &local");
    switch (listed) {
        .list => |args| try std.testing.expectEqualStrings("&local", args.channel),
        else => return error.TestUnexpectedResult,
    }

    const resolved = try parseCommand("SVCTEMPLATE RESOLVE #ops speaker");
    switch (resolved) {
        .resolve => |args| try std.testing.expectEqualStrings("speaker", args.role),
        else => return error.TestUnexpectedResult,
    }
}

test "parse channel flag sets from mode letters and names" {
    const letters = try parseFlagSet("+imntS-r");
    try std.testing.expect(letters.has(.invite_only));
    try std.testing.expect(letters.has(.moderated));
    try std.testing.expect(letters.has(.no_external));
    try std.testing.expect(letters.has(.topic_ops));
    try std.testing.expect(letters.has(.tls_only));
    try std.testing.expect(!letters.has(.registered));

    const names = try parseFlagSet("moderated,topic-ops,auth_only,NOCTCP");
    try std.testing.expect(names.has(.moderated));
    try std.testing.expect(names.has(.topic_ops));
    try std.testing.expect(names.has(.authonly));
    try std.testing.expect(names.has(.no_ctcp));

    const none = try parseFlagSet("none");
    try std.testing.expect(none.isEmpty());

    try std.testing.expectError(error.EmptyFlagSet, parseFlagSet(""));
    try std.testing.expectError(error.EmptyFlagSet, parseFlagSet("+"));
    try std.testing.expectError(error.InvalidFlag, parseFlagSet("+?"));
    try std.testing.expectError(error.InvalidFlag, parseFlagSet("moderated,,secret"));
}

test "define resolve overwrite undefine and count templates" {
    const allocator = std.testing.allocator;
    var store = TemplateStore.initBounded(allocator, 4);
    defer store.deinit();

    const founder = FlagSet.fromFlags(&.{ .registered, .service, .topic_ops });
    const speaker = FlagSet.fromFlags(&.{ .moderated, .no_external });

    try std.testing.expect(try store.define("#ops", "founder", founder));
    try std.testing.expect(try store.define("#ops", "speaker", speaker));
    try std.testing.expectEqual(@as(usize, 2), store.count());

    try std.testing.expect(store.resolve("#ops", "founder").?.eql(founder));
    try std.testing.expect(store.resolve("#ops", "speaker").?.eql(speaker));
    try std.testing.expect(store.resolve("#ops", "missing") == null);

    const replacement = FlagSet.one(.secret);
    try std.testing.expect(!(try store.define("#ops", "speaker", replacement)));
    try std.testing.expectEqual(@as(usize, 2), store.count());
    try std.testing.expect(store.resolve("#ops", "speaker").?.eql(replacement));

    try std.testing.expect(store.undefine("#ops", "speaker"));
    try std.testing.expect(!store.undefine("#ops", "speaker"));
    try std.testing.expect(store.resolve("#ops", "speaker") == null);
    try std.testing.expectEqual(@as(usize, 1), store.count());
}

test "templates are per channel and list exposes owned roles" {
    const allocator = std.testing.allocator;
    var store = TemplateStore.init(allocator);
    defer store.deinit();

    const ops_founder = FlagSet.fromFlags(&.{ .registered, .service });
    const games_founder = FlagSet.fromFlags(&.{ .moderated, .topic_ops });
    const ops_voice = FlagSet.one(.no_external);

    try std.testing.expect(try store.define("#ops", "founder", ops_founder));
    try std.testing.expect(try store.define("#games", "founder", games_founder));
    try std.testing.expect(try store.define("#ops", "voice", ops_voice));

    try std.testing.expect(store.resolve("#ops", "founder").?.eql(ops_founder));
    try std.testing.expect(store.resolve("#games", "founder").?.eql(games_founder));

    var entries: [4]TemplateEntry = undefined;
    const listed = try store.list("#ops", &entries);
    try std.testing.expectEqual(@as(usize, 2), listed.len);
    try expectListed(listed, "founder", ops_founder);
    try expectListed(listed, "voice", ops_voice);

    var too_small: [1]TemplateEntry = undefined;
    try std.testing.expectError(error.BufferTooSmall, store.list("#ops", &too_small));
}

test "store enforces bounds without leaking failed inserts" {
    const allocator = std.testing.allocator;
    var store = TemplateStore.initBounded(allocator, 2);
    defer store.deinit();

    try std.testing.expect(try store.define("#a", "one", FlagSet.one(.secret)));
    try std.testing.expect(try store.define("#a", "two", FlagSet.one(.moderated)));
    try std.testing.expectEqual(@as(usize, 2), store.count());

    try std.testing.expectError(error.TooManyTemplates, store.define("#a", "three", FlagSet.one(.topic_ops)));
    try std.testing.expectEqual(@as(usize, 2), store.count());
    try std.testing.expect(store.resolve("#a", "three") == null);

    const long_role = "r" ** (max_role_len + 1);
    try std.testing.expectError(error.InvalidRole, store.define("#a", long_role, FlagSet.one(.secret)));
    try std.testing.expectError(error.InvalidChannel, store.define("not-a-channel", "role", FlagSet.one(.secret)));
}

test "apply parsed commands drives pure store logic" {
    const allocator = std.testing.allocator;
    var store = TemplateStore.init(allocator);
    defer store.deinit();

    var list_out: [8]TemplateEntry = undefined;
    const defined = try store.apply(try parseCommand("SVCTEMPLATE DEFINE #chan host +mtn"), &list_out);
    switch (defined) {
        .defined => |created| try std.testing.expect(created),
        else => return error.TestUnexpectedResult,
    }

    const resolved = try store.apply(try parseCommand("SVCTEMPLATE RESOLVE #chan host"), &list_out);
    switch (resolved) {
        .resolved => |flags_opt| {
            const flags = flags_opt orelse return error.TestUnexpectedResult;
            try std.testing.expect(flags.has(.moderated));
            try std.testing.expect(flags.has(.topic_ops));
            try std.testing.expect(flags.has(.no_external));
        },
        else => return error.TestUnexpectedResult,
    }

    const listed = try store.apply(try parseCommand("SVCTEMPLATE LIST #chan"), &list_out);
    switch (listed) {
        .listed => |entries| {
            try std.testing.expectEqual(@as(usize, 1), entries.len);
            try std.testing.expectEqualStrings("host", entries[0].role);
        },
        else => return error.TestUnexpectedResult,
    }

    const undef_result = try store.apply(try parseCommand("SVCTEMPLATE UNDEFINE #chan host"), &list_out);
    switch (undef_result) {
        .undefined => |removed| try std.testing.expect(removed),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(store.resolve("#chan", "host") == null);
}

test "clear channel uses exact channel prefix only" {
    const allocator = std.testing.allocator;
    var store = TemplateStore.init(allocator);
    defer store.deinit();

    try std.testing.expect(try store.define("#alpha", "one", FlagSet.one(.secret)));
    try std.testing.expect(try store.define("#alpha", "two", FlagSet.one(.moderated)));
    try std.testing.expect(try store.define("#alphaX", "one", FlagSet.one(.topic_ops)));

    try std.testing.expectEqual(@as(usize, 2), store.clearChannel("#alpha"));
    try std.testing.expect(store.resolve("#alpha", "one") == null);
    try std.testing.expect(store.resolve("#alpha", "two") == null);
    try std.testing.expect(store.resolve("#alphaX", "one") != null);
    try std.testing.expectEqual(@as(usize, 1), store.count());
}

test "render flag letters uses stable service-facing order" {
    var out: [32]u8 = undefined;
    const flags = FlagSet.fromFlags(&.{ .topic_ops, .invite_only, .service, .registered });
    try std.testing.expectEqualStrings("+itrz", try renderFlagLetters(flags, &out));
    try std.testing.expectEqualStrings("", try renderFlagLetters(FlagSet.empty(), &out));

    var tiny: [2]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, renderFlagLetters(flags, &tiny));
}

fn expectListed(entries: []const TemplateEntry, role: []const u8, flags: FlagSet) !void {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.role, role)) {
            try std.testing.expect(entry.flags.eql(flags));
            return;
        }
    }
    return error.TestUnexpectedResult;
}
