//! In-process IRC services over MizuStore with typed results and no IRC I/O.
const std = @import("std");

const store_mod = @import("store.zig");

pub const MizuStore = store_mod.MizuStore;

const account_max = 32;
const channel_max = 64;
const nick_max = 64;
const email_max = 96;
const mask_max = 160;
const reason_max = 128;
const key_max = 256;
const record_max = 768;
const salt_len = 16;
const hash_len = 32;
const salt_hex_len = salt_len * 2;
const hash_hex_len = hash_len * 2;
const generation_len = 16;
const generation_hex_len = generation_len * 2;
const pbkdf2_rounds: u32 = 100_000;

const account_version = "A1";
const channel_version = "C1";
const access_version = "X1";
const akick_version = "K1";
const access_prefix = "chanaccess:";
const akick_prefix = "chanakick:";

pub const channel_access_family = store_mod.Family.props;

pub const ServiceError = anyerror;

/// Optional integration hook for the daemon's SUIMYAKU state.
pub const StateHook = struct {
    ptr: *anyopaque,
    create_channel: *const fn (ctx: *anyopaque, channel: []const u8) ServiceError!void,

    pub fn createChannel(self: StateHook, channel: []const u8) ServiceError!void {
        try self.create_channel(self.ptr, channel);
    }
};

pub fn InlineText(comptime max_len: usize) type {
    return struct {
        bytes: [max_len]u8 = [_]u8{0} ** max_len,
        len: u16 = 0,

        pub fn init(input: []const u8) error{StringTooLong}!@This() {
            if (input.len > max_len) return error.StringTooLong;
            var out = @This(){};
            if (input.len != 0) @memcpy(out.bytes[0..input.len], input);
            out.len = @intCast(input.len);
            return out;
        }

        pub fn empty() @This() {
            return .{};
        }

        pub fn asSlice(self: *const @This()) []const u8 {
            return self.bytes[0..self.len];
        }
    };
}

pub const AccountName = InlineText(account_max);
pub const ChannelName = InlineText(channel_max);
pub const NickName = InlineText(nick_max);
pub const Email = InlineText(email_max);
pub const Mask = InlineText(mask_max);
pub const Reason = InlineText(reason_max);

pub const AccessLevel = enum(u8) {
    voice = 10,
    op = 25,
    admin = 50,
    founder = 100,

    pub fn allows(self: AccessLevel, needed: AccessLevel) bool {
        return @intFromEnum(self) >= @intFromEnum(needed);
    }
};

pub const AccountSetField = union(enum) { email: []const u8, flags: u32 };
pub const ChannelSetField = union(enum) { flags: u32 };
pub const AccessAction = enum { query, grant, revoke };
pub const AkickAction = enum { add, remove, query };
pub const AccountRef = struct { name: AccountName };
pub const ChannelRef = struct { name: ChannelName };

pub const AccountInfo = struct {
    name: AccountName,
    email: Email = Email.empty(),
    flags: u32 = 0,
};

pub const ChannelInfo = struct {
    name: ChannelName,
    founder: AccountName,
    flags: u32 = 0,
};

pub const GhostInfo = struct {
    account: AccountName,
    nick: NickName,
};

pub const AccessInfo = struct {
    channel: ChannelName,
    account: AccountName,
    level: AccessLevel,
};

pub const AkickInfo = struct {
    channel: ChannelName,
    mask: Mask,
    setter: AccountName,
    reason: Reason = Reason.empty(),
};

pub const CommandResult = union(enum) {
    registered_account: AccountRef,
    identified: AccountRef,
    dropped_account: AccountRef,
    ghosted: GhostInfo,
    set_account: AccountInfo,
    account_info: AccountInfo,
    registered_channel: ChannelInfo,
    dropped_channel: ChannelRef,
    channel_info: ChannelInfo,
    access: AccessInfo,
    access_revoked: AccessInfo,
    akick: AkickInfo,
    akick_removed: AkickInfo,
    set_channel: ChannelInfo,
};

const AccountRecord = struct {
    name: AccountName,
    salt: [salt_len]u8,
    hash: [hash_len]u8,
    email: Email = Email.empty(),
    flags: u32 = 0,

    fn info(self: AccountRecord) AccountInfo {
        return .{ .name = self.name, .email = self.email, .flags = self.flags };
    }
};

const ChannelRecord = struct {
    name: ChannelName,
    founder: AccountName,
    generation: [generation_len]u8,
    flags: u32 = 0,

    fn info(self: ChannelRecord) ChannelInfo {
        return .{ .name = self.name, .founder = self.founder, .flags = self.flags };
    }
};

const AccessRecord = struct {
    channel: ChannelName,
    account: AccountName,
    generation: [generation_len]u8,
    level: AccessLevel,

    fn info(self: AccessRecord) AccessInfo {
        return .{ .channel = self.channel, .account = self.account, .level = self.level };
    }
};

const AkickRecord = struct {
    channel: ChannelName,
    mask: Mask,
    generation: [generation_len]u8,
    setter: AccountName,
    reason: Reason = Reason.empty(),

    fn info(self: AkickRecord) AkickInfo {
        return .{ .channel = self.channel, .mask = self.mask, .setter = self.setter, .reason = self.reason };
    }
};

pub const Services = struct {
    store: *MizuStore,
    state: ?StateHook = null,

    pub fn init(store: *MizuStore, state: ?StateHook) Services {
        return .{ .store = store, .state = state };
    }

    pub fn registerAccount(self: *Services, name: []const u8, password: []const u8, scratch: []u8) ServiceError!CommandResult {
        const key = try accountKey(name);
        if (self.store.family(.accounts).get(key.asSlice()) != null) return error.AlreadyExists;
        try validatePassword(password);

        var salt: [salt_len]u8 = undefined;
        self.store.io.randomSecure(&salt) catch self.store.io.random(&salt);

        var hash: [hash_len]u8 = undefined;
        try hashPassword(&hash, password, &salt);

        const record = AccountRecord{
            .name = try AccountName.init(key.asSlice()),
            .salt = salt,
            .hash = hash,
        };
        const encoded = try encodeAccount(record, scratch);
        try self.store.family(.accounts).put(key.asSlice(), encoded);
        return .{ .registered_account = .{ .name = record.name } };
    }

    pub fn identifyAccount(self: *Services, name: []const u8, password: []const u8) ServiceError!CommandResult {
        const record = try self.loadAccount(name);
        try verifyPassword(record, password);
        return .{ .identified = .{ .name = record.name } };
    }

    pub fn dropAccount(self: *Services, name: []const u8, password: []const u8) ServiceError!CommandResult {
        const record = try self.loadAccount(name);
        try verifyPassword(record, password);
        try self.store.family(.accounts).delete(record.name.asSlice());
        return .{ .dropped_account = .{ .name = record.name } };
    }

    pub fn ghostAccount(self: *Services, name: []const u8, password: []const u8, nick: []const u8) ServiceError!CommandResult {
        const record = try self.loadAccount(name);
        try verifyPassword(record, password);
        const clean_nick = try validateNick(nick);
        return .{ .ghosted = .{ .account = record.name, .nick = clean_nick } };
    }

    pub fn setAccount(
        self: *Services,
        name: []const u8,
        password: []const u8,
        field: AccountSetField,
        scratch: []u8,
    ) ServiceError!CommandResult {
        var record = try self.loadAccount(name);
        try verifyPassword(record, password);
        switch (field) {
            .email => |email| record.email = try validateEmail(email),
            .flags => |flags| record.flags = flags,
        }
        const encoded = try encodeAccount(record, scratch);
        try self.store.family(.accounts).put(record.name.asSlice(), encoded);
        return .{ .set_account = record.info() };
    }

    pub fn accountInfo(self: *Services, name: []const u8) ServiceError!CommandResult {
        const record = try self.loadAccount(name);
        return .{ .account_info = record.info() };
    }

    pub fn registerChannel(self: *Services, channel: []const u8, founder: []const u8, scratch: []u8) ServiceError!CommandResult {
        const channel_key = try channelKey(channel);
        if (self.store.family(.chanregs).get(channel_key.asSlice()) != null) return error.AlreadyExists;
        const founder_key = try accountKey(founder);
        if (self.store.family(.accounts).get(founder_key.asSlice()) == null) return error.NotFound;

        var generation: [generation_len]u8 = undefined;
        self.store.io.randomSecure(&generation) catch self.store.io.random(&generation);

        const record = ChannelRecord{
            .name = try ChannelName.init(channel_key.asSlice()),
            .founder = try AccountName.init(founder_key.asSlice()),
            .generation = generation,
        };
        const encoded = try encodeChannel(record, scratch);
        try self.store.family(.chanregs).put(record.name.asSlice(), encoded);
        _ = try self.putAccess(record, record.founder, .founder, scratch);

        if (self.state) |hook| try hook.createChannel(record.name.asSlice());

        return .{ .registered_channel = record.info() };
    }

    pub fn dropChannel(self: *Services, channel: []const u8, actor: []const u8) ServiceError!CommandResult {
        const record = try self.loadChannel(channel);
        try self.requireAccess(record, actor, .founder);
        try self.store.family(.chanregs).delete(record.name.asSlice());
        return .{ .dropped_channel = .{ .name = record.name } };
    }

    pub fn channelAccess(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        target: []const u8,
        action: AccessAction,
        level: AccessLevel,
        scratch: []u8,
    ) ServiceError!CommandResult {
        const record = try self.loadChannel(channel);
        const target_key = try accountKey(target);
        if (self.store.family(.accounts).get(target_key.asSlice()) == null) return error.NotFound;

        switch (action) {
            .query => {
                const access = try self.loadAccess(record, target_key.asSlice());
                return .{ .access = access.info() };
            },
            .grant => {
                try self.requireAccess(record, actor, .admin);
                if (level == .founder) try self.requireAccess(record, actor, .founder);
                const access = try self.putAccess(record, try AccountName.init(target_key.asSlice()), level, scratch);
                return .{ .access = access.info() };
            },
            .revoke => {
                try self.requireAccess(record, actor, .admin);
                if (std.mem.eql(u8, target_key.asSlice(), record.founder.asSlice())) return error.Forbidden;
                const existing = self.loadAccess(record, target_key.asSlice()) catch |err| switch (err) {
                    error.NotFound => AccessRecord{
                        .channel = record.name,
                        .account = try AccountName.init(target_key.asSlice()),
                        .generation = record.generation,
                        .level = level,
                    },
                    else => return err,
                };
                var key_buf: [key_max]u8 = undefined;
                const key = try accessKey(record.name.asSlice(), target_key.asSlice(), &key_buf);
                try self.store.delete(channel_access_family, key);
                return .{ .access_revoked = existing.info() };
            },
        }
    }

    pub fn channelAkick(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        mask: []const u8,
        action: AkickAction,
        reason: []const u8,
        scratch: []u8,
    ) ServiceError!CommandResult {
        const record = try self.loadChannel(channel);
        const clean_mask = try validateMask(mask);
        switch (action) {
            .query => {
                const akick = try self.loadAkick(record, clean_mask.asSlice());
                return .{ .akick = akick.info() };
            },
            .add => {
                try self.requireAccess(record, actor, .admin);
                const actor_key = try accountKey(actor);
                const akick = AkickRecord{
                    .channel = record.name,
                    .mask = clean_mask,
                    .generation = record.generation,
                    .setter = try AccountName.init(actor_key.asSlice()),
                    .reason = try validateReason(reason),
                };
                const encoded = try encodeAkick(akick, scratch);
                var key_buf: [key_max]u8 = undefined;
                const key = try akickKey(record.name.asSlice(), clean_mask.asSlice(), &key_buf);
                try self.store.put(channel_access_family, key, encoded);
                return .{ .akick = akick.info() };
            },
            .remove => {
                try self.requireAccess(record, actor, .admin);
                const existing = self.loadAkick(record, clean_mask.asSlice()) catch |err| switch (err) {
                    error.NotFound => AkickRecord{
                        .channel = record.name,
                        .mask = clean_mask,
                        .generation = record.generation,
                        .setter = try AccountName.init((try accountKey(actor)).asSlice()),
                    },
                    else => return err,
                };
                var key_buf: [key_max]u8 = undefined;
                const key = try akickKey(record.name.asSlice(), clean_mask.asSlice(), &key_buf);
                try self.store.delete(channel_access_family, key);
                return .{ .akick_removed = existing.info() };
            },
        }
    }

    pub fn setChannel(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        field: ChannelSetField,
        scratch: []u8,
    ) ServiceError!CommandResult {
        var record = try self.loadChannel(channel);
        try self.requireAccess(record, actor, .admin);
        switch (field) {
            .flags => |flags| record.flags = flags,
        }
        const encoded = try encodeChannel(record, scratch);
        try self.store.family(.chanregs).put(record.name.asSlice(), encoded);
        return .{ .set_channel = record.info() };
    }

    pub fn channelInfo(self: *Services, channel: []const u8) ServiceError!CommandResult {
        const record = try self.loadChannel(channel);
        return .{ .channel_info = record.info() };
    }

    fn loadAccount(self: *Services, name: []const u8) ServiceError!AccountRecord {
        const key = try accountKey(name);
        const value = self.store.family(.accounts).get(key.asSlice()) orelse return error.NotFound;
        return decodeAccount(value);
    }

    fn loadChannel(self: *Services, channel: []const u8) ServiceError!ChannelRecord {
        const key = try channelKey(channel);
        const value = self.store.family(.chanregs).get(key.asSlice()) orelse return error.NotFound;
        return decodeChannel(value);
    }

    fn putAccess(
        self: *Services,
        channel: ChannelRecord,
        account: AccountName,
        level: AccessLevel,
        scratch: []u8,
    ) ServiceError!AccessRecord {
        const record = AccessRecord{
            .channel = channel.name,
            .account = account,
            .generation = channel.generation,
            .level = level,
        };
        const encoded = try encodeAccess(record, scratch);
        var key_buf: [key_max]u8 = undefined;
        const key = try accessKey(channel.name.asSlice(), account.asSlice(), &key_buf);
        try self.store.put(channel_access_family, key, encoded);
        return record;
    }

    fn loadAccess(self: *Services, channel: ChannelRecord, account: []const u8) ServiceError!AccessRecord {
        var key_buf: [key_max]u8 = undefined;
        const key = try accessKey(channel.name.asSlice(), account, &key_buf);
        const value = self.store.get(channel_access_family, key) orelse return error.NotFound;
        const record = try decodeAccess(value);
        if (!sameBytes(generation_len, &record.generation, &channel.generation)) return error.NotFound;
        return record;
    }

    fn loadAkick(self: *Services, channel: ChannelRecord, mask: []const u8) ServiceError!AkickRecord {
        var key_buf: [key_max]u8 = undefined;
        const key = try akickKey(channel.name.asSlice(), mask, &key_buf);
        const value = self.store.get(channel_access_family, key) orelse return error.NotFound;
        const record = try decodeAkick(value);
        if (!sameBytes(generation_len, &record.generation, &channel.generation)) return error.NotFound;
        return record;
    }

    fn requireAccess(self: *Services, channel: ChannelRecord, actor: []const u8, needed: AccessLevel) ServiceError!void {
        const actor_key = try accountKey(actor);
        if (std.mem.eql(u8, actor_key.asSlice(), channel.founder.asSlice())) return;
        const access = try self.loadAccess(channel, actor_key.asSlice());
        if (!access.level.allows(needed)) return error.Forbidden;
    }
};

fn validatePassword(password: []const u8) ServiceError!void {
    if (password.len < 8 or password.len > 512) return error.InvalidPassword;
    for (password) |byte| if (byte == 0 or byte == '\n' or byte == '\r') return error.InvalidPassword;
}

fn validateEmail(input: []const u8) ServiceError!Email {
    if (input.len == 0) return Email.empty();
    if (input.len > email_max or hasCtlOrSep(input)) return error.InvalidValue;
    return Email.init(input);
}

fn validateReason(input: []const u8) ServiceError!Reason {
    if (input.len > reason_max or hasCtlOrSep(input)) return error.InvalidValue;
    return Reason.init(input);
}

fn validateNick(input: []const u8) ServiceError!NickName {
    if (input.len == 0 or input.len > nick_max or hasCtlOrSep(input)) return error.InvalidName;
    for (input) |byte| if (byte == ' ' or byte == ',') return error.InvalidName;
    return NickName.init(input);
}

fn validateMask(input: []const u8) ServiceError!Mask {
    if (input.len == 0 or input.len > mask_max or hasCtlOrSep(input)) return error.InvalidValue;
    return Mask.init(input);
}

fn accountKey(input: []const u8) ServiceError!AccountName {
    if (input.len == 0 or input.len > account_max) return error.InvalidName;
    var out = AccountName{};
    for (input, 0..) |byte, idx| {
        if (!isAccountChar(byte)) return error.InvalidName;
        out.bytes[idx] = asciiLower(byte);
    }
    out.len = @intCast(input.len);
    return out;
}

fn channelKey(input: []const u8) ServiceError!ChannelName {
    if (input.len < 2 or input.len > channel_max or input[0] != '#') return error.InvalidChannel;
    var out = ChannelName{};
    for (input, 0..) |byte, idx| {
        if (byte <= 0x20 or byte == 0x7f or byte == '|' or byte == ',' or byte == ':') return error.InvalidChannel;
        out.bytes[idx] = asciiLower(byte);
    }
    out.len = @intCast(input.len);
    return out;
}

fn isAccountChar(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or
        (byte >= 'A' and byte <= 'Z') or
        (byte >= '0' and byte <= '9') or
        byte == '_' or byte == '-' or byte == '.';
}

fn asciiLower(byte: u8) u8 {
    if (byte >= 'A' and byte <= 'Z') return byte + ('a' - 'A');
    return byte;
}

fn hasCtlOrSep(input: []const u8) bool {
    for (input) |byte| if (byte < 0x20 or byte == 0x7f or byte == '|') return true;
    return false;
}

fn hashPassword(out: *[hash_len]u8, password: []const u8, salt: *const [salt_len]u8) ServiceError!void {
    try std.crypto.pwhash.pbkdf2(out, password, salt, pbkdf2_rounds, std.crypto.auth.hmac.sha2.HmacSha256);
}

fn verifyPassword(record: AccountRecord, password: []const u8) ServiceError!void {
    try validatePassword(password);
    var candidate: [hash_len]u8 = undefined;
    try hashPassword(&candidate, password, &record.salt);
    if (!std.crypto.timing_safe.eql([hash_len]u8, candidate, record.hash)) return error.AuthFailed;
}

fn encodeAccount(record: AccountRecord, scratch: []u8) ServiceError![]const u8 {
    var salt_hex = std.fmt.bytesToHex(record.salt, .lower);
    var hash_hex = std.fmt.bytesToHex(record.hash, .lower);
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{s}|{s}|{}|{s}",
        .{ account_version, record.name.asSlice(), &salt_hex, &hash_hex, record.flags, record.email.asSlice() },
    ) catch error.BufferTooSmall;
}

fn decodeAccount(value: []const u8) ServiceError!AccountRecord {
    var it = std.mem.splitScalar(u8, value, '|');
    if (!std.mem.eql(u8, it.next() orelse return error.InvalidRecord, account_version)) return error.InvalidRecord;
    const name = try accountKey(it.next() orelse return error.InvalidRecord);
    const salt_hex = it.next() orelse return error.InvalidRecord;
    const hash_hex = it.next() orelse return error.InvalidRecord;
    const flags_text = it.next() orelse return error.InvalidRecord;
    const email_text = it.next() orelse "";
    if (it.next() != null) return error.InvalidRecord;
    if (salt_hex.len != salt_hex_len or hash_hex.len != hash_hex_len) return error.InvalidRecord;

    var record = AccountRecord{
        .name = name,
        .salt = undefined,
        .hash = undefined,
        .flags = std.fmt.parseInt(u32, flags_text, 10) catch return error.InvalidRecord,
        .email = try validateEmail(email_text),
    };
    _ = std.fmt.hexToBytes(&record.salt, salt_hex) catch return error.InvalidRecord;
    _ = std.fmt.hexToBytes(&record.hash, hash_hex) catch return error.InvalidRecord;
    return record;
}

fn encodeChannel(record: ChannelRecord, scratch: []u8) ServiceError![]const u8 {
    var gen_hex = std.fmt.bytesToHex(record.generation, .lower);
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{s}|{s}|{}",
        .{ channel_version, record.name.asSlice(), record.founder.asSlice(), &gen_hex, record.flags },
    ) catch error.BufferTooSmall;
}

fn decodeChannel(value: []const u8) ServiceError!ChannelRecord {
    var it = std.mem.splitScalar(u8, value, '|');
    if (!std.mem.eql(u8, it.next() orelse return error.InvalidRecord, channel_version)) return error.InvalidRecord;
    const name = try channelKey(it.next() orelse return error.InvalidRecord);
    const founder = try accountKey(it.next() orelse return error.InvalidRecord);
    const gen_hex = it.next() orelse return error.InvalidRecord;
    const flags_text = it.next() orelse return error.InvalidRecord;
    if (it.next() != null or gen_hex.len != generation_hex_len) return error.InvalidRecord;
    var record = ChannelRecord{
        .name = name,
        .founder = founder,
        .generation = undefined,
        .flags = std.fmt.parseInt(u32, flags_text, 10) catch return error.InvalidRecord,
    };
    _ = std.fmt.hexToBytes(&record.generation, gen_hex) catch return error.InvalidRecord;
    return record;
}

fn encodeAccess(record: AccessRecord, scratch: []u8) ServiceError![]const u8 {
    var gen_hex = std.fmt.bytesToHex(record.generation, .lower);
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{s}|{s}|{}",
        .{ access_version, record.channel.asSlice(), record.account.asSlice(), &gen_hex, @intFromEnum(record.level) },
    ) catch error.BufferTooSmall;
}

fn decodeAccess(value: []const u8) ServiceError!AccessRecord {
    var it = std.mem.splitScalar(u8, value, '|');
    if (!std.mem.eql(u8, it.next() orelse return error.InvalidRecord, access_version)) return error.InvalidRecord;
    const channel = try channelKey(it.next() orelse return error.InvalidRecord);
    const account = try accountKey(it.next() orelse return error.InvalidRecord);
    const gen_hex = it.next() orelse return error.InvalidRecord;
    const level_text = it.next() orelse return error.InvalidRecord;
    if (it.next() != null or gen_hex.len != generation_hex_len) return error.InvalidRecord;
    var record = AccessRecord{
        .channel = channel,
        .account = account,
        .generation = undefined,
        .level = levelFromInt(std.fmt.parseInt(u8, level_text, 10) catch return error.InvalidRecord) orelse return error.InvalidRecord,
    };
    _ = std.fmt.hexToBytes(&record.generation, gen_hex) catch return error.InvalidRecord;
    return record;
}

fn encodeAkick(record: AkickRecord, scratch: []u8) ServiceError![]const u8 {
    var gen_hex = std.fmt.bytesToHex(record.generation, .lower);
    return std.fmt.bufPrint(
        scratch,
        "{s}|{s}|{s}|{s}|{s}|{s}",
        .{ akick_version, record.channel.asSlice(), record.mask.asSlice(), &gen_hex, record.setter.asSlice(), record.reason.asSlice() },
    ) catch error.BufferTooSmall;
}

fn decodeAkick(value: []const u8) ServiceError!AkickRecord {
    var it = std.mem.splitScalar(u8, value, '|');
    if (!std.mem.eql(u8, it.next() orelse return error.InvalidRecord, akick_version)) return error.InvalidRecord;
    const channel = try channelKey(it.next() orelse return error.InvalidRecord);
    const mask = try validateMask(it.next() orelse return error.InvalidRecord);
    const gen_hex = it.next() orelse return error.InvalidRecord;
    const setter = try accountKey(it.next() orelse return error.InvalidRecord);
    const reason = try validateReason(it.next() orelse "");
    if (it.next() != null or gen_hex.len != generation_hex_len) return error.InvalidRecord;
    var record = AkickRecord{
        .channel = channel,
        .mask = mask,
        .generation = undefined,
        .setter = setter,
        .reason = reason,
    };
    _ = std.fmt.hexToBytes(&record.generation, gen_hex) catch return error.InvalidRecord;
    return record;
}

fn levelFromInt(value: u8) ?AccessLevel {
    return switch (value) {
        @intFromEnum(AccessLevel.voice) => .voice,
        @intFromEnum(AccessLevel.op) => .op,
        @intFromEnum(AccessLevel.admin) => .admin,
        @intFromEnum(AccessLevel.founder) => .founder,
        else => null,
    };
}

fn accessKey(channel: []const u8, account: []const u8, out: []u8) ServiceError![]const u8 {
    return prefixedKey(access_prefix, channel, account, out);
}

fn akickKey(channel: []const u8, mask: []const u8, out: []u8) ServiceError![]const u8 {
    return prefixedKey(akick_prefix, channel, mask, out);
}

fn prefixedKey(prefix: []const u8, channel: []const u8, tail: []const u8, out: []u8) ServiceError![]const u8 {
    if (prefix.len + channel.len + 1 + tail.len > out.len) return error.BufferTooSmall;
    var len: usize = 0;
    @memcpy(out[len..][0..prefix.len], prefix);
    len += prefix.len;
    @memcpy(out[len..][0..channel.len], channel);
    len += channel.len;
    out[len] = ':';
    len += 1;
    @memcpy(out[len..][0..tail.len], tail);
    len += tail.len;
    return out[0..len];
}

fn sameBytes(comptime len: usize, a: *const [len]u8, b: *const [len]u8) bool {
    return std.crypto.timing_safe.eql([len]u8, a.*, b.*);
}

fn openTestStore(tmp: std.testing.TmpDir, name: []const u8) !MizuStore {
    return MizuStore.open(std.testing.allocator, std.testing.io, tmp.dir, name);
}

test "register and identify account" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-account.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    const registered = try services.registerAccount("Alice", "correct horse battery staple", &scratch);
    try std.testing.expectEqualStrings("alice", registered.registered_account.name.asSlice());

    const identified = try services.identifyAccount("ALICE", "correct horse battery staple");
    try std.testing.expectEqualStrings("alice", identified.identified.name.asSlice());
}

test "wrong password is rejected" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-wrong-pass.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    try std.testing.expectError(error.AuthFailed, services.identifyAccount("alice", "wrong horse battery staple"));
}

test "account persists across store reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-persist.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        var scratch: [record_max]u8 = undefined;
        _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
        _ = try services.setAccount("alice", "correct horse battery staple", .{ .email = "alice@example.test" }, &scratch);
    }
    {
        var store = try openTestStore(tmp, "services-persist.wal");
        defer store.deinit();
        var services = Services.init(&store, null);
        const result = try services.accountInfo("ALICE");
        try std.testing.expectEqualStrings("alice@example.test", result.account_info.email.asSlice());
        _ = try services.identifyAccount("alice", "correct horse battery staple");
    }
}

test "channel register and access grant" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-channel.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerAccount("bob", "another correct battery staple", &scratch);
    const registered = try services.registerChannel("#Mizuchi", "alice", &scratch);
    try std.testing.expectEqualStrings("#mizuchi", registered.registered_channel.name.asSlice());
    try std.testing.expectEqualStrings("alice", registered.registered_channel.founder.asSlice());

    const granted = try services.channelAccess("#mizuchi", "alice", "bob", .grant, .op, &scratch);
    try std.testing.expectEqual(AccessLevel.op, granted.access.level);

    const queried = try services.channelAccess("#mizuchi", "bob", "bob", .query, .voice, &scratch);
    try std.testing.expectEqual(AccessLevel.op, queried.access.level);
}

test "drop account and channel" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try openTestStore(tmp, "services-drop.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var scratch: [record_max]u8 = undefined;

    _ = try services.registerAccount("alice", "correct horse battery staple", &scratch);
    _ = try services.registerChannel("#mizuchi", "alice", &scratch);
    _ = try services.dropChannel("#mizuchi", "alice");
    try std.testing.expectError(error.NotFound, services.channelInfo("#mizuchi"));

    _ = try services.dropAccount("alice", "correct horse battery staple");
    try std.testing.expectError(error.NotFound, services.accountInfo("alice"));
}
