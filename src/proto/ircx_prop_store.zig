//! Allocator-backed IRCX PROP storage, parsing, and reply rendering.
const std = @import("std");
const irc_line = @import("irc_line.zig");
const ircx = @import("ircx.zig");
const limits_config = @import("limits_config.zig");

pub const default_max_entities: usize = 1024;
pub const default_max_props_per_entity: usize = 64;
pub const default_max_entity_id: usize = ircx.MAX_ENTITY_ID;
pub const default_max_key: usize = ircx.MAX_PROP_NAME;
pub const default_max_value: usize = ircx.MAX_PROP_VALUE;
pub const default_max_owner_bytes: usize = 128;
pub const default_max_request_keys: usize = 16;

pub const Params = struct {
    max_entities: usize = default_max_entities,
    max_props_per_entity: usize = default_max_props_per_entity,
    max_entity_id: usize = default_max_entity_id,
    max_key: usize = default_max_key,
    max_value: usize = default_max_value,
    max_owner_bytes: usize = default_max_owner_bytes,
    max_request_keys: usize = default_max_request_keys,

    /// Derive `Params` from the central policy limits (config-driven).
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_entities = limits.ircx_max_entities,
            .max_props_per_entity = limits.ircx_props_per_entity,
            .max_entity_id = limits.ircx_entity_id_len,
            .max_key = limits.ircx_prop_name_len,
            .max_value = limits.ircx_prop_value_len,
            .max_owner_bytes = limits.ircx_prop_owner_len,
            .max_request_keys = limits.ircx_prop_request_keys,
        };
    }
};

pub const PropError = irc_line.ParseError || error{
    AccessDenied,
    InvalidCommand,
    InvalidEntity,
    InvalidKey,
    InvalidOwner,
    InvalidValue,
    LimitReached,
    NeedMoreParams,
    OutputTooSmall,
    PropMissing,
    ReadOnlyProperty,
    TooManyParams,
};

pub const EntityKind = enum {
    channel,
    user,
    member,

    pub fn token(self: EntityKind) []const u8 {
        return switch (self) {
            .channel => "channel",
            .user => "user",
            .member => "member",
        };
    }
};

pub const Entity = struct {
    kind: EntityKind,
    id: []const u8,

    pub fn fromId(id: []const u8) PropError!Entity {
        if (id.len == 0) return error.InvalidEntity;
        const kind: EntityKind = switch (id[0]) {
            '#', '&', '+', '%' => .channel,
            else => if (std.mem.indexOfScalar(u8, id, ':') != null) .member else .user,
        };
        const entity = Entity{ .kind = kind, .id = id };
        try validateEntity(entity, default_max_entity_id);
        return entity;
    }
};

pub const AccessLevel = enum(u8) {
    user = 0,
    member = 1,
    host = 2,
    owner = 3,
    sysop = 4,
    sysop_manager = 5,
    server = 6,

    pub fn allows(self: AccessLevel, required: AccessLevel) bool {
        return @intFromEnum(self) >= @intFromEnum(required);
    }
};

pub const Setter = struct {
    id: []const u8,
    access: AccessLevel,
};

pub const ChannelPropKey = enum {
    oid,
    name,
    creation,
    language,
    ownerkey,
    hostkey,
    memberkey,
    pics,
    topic,
    subject,
    client,
    onjoin,
    onpart,
    lag,
    account,
    clientguid,
    servicepath,

    pub fn token(self: ChannelPropKey) []const u8 {
        return switch (self) {
            .oid => "OID",
            .name => "NAME",
            .creation => "CREATION",
            .language => "LANGUAGE",
            .ownerkey => "OWNERKEY",
            .hostkey => "HOSTKEY",
            .memberkey => "MEMBERKEY",
            .pics => "PICS",
            .topic => "TOPIC",
            .subject => "SUBJECT",
            .client => "CLIENT",
            .onjoin => "ONJOIN",
            .onpart => "ONPART",
            .lag => "LAG",
            .account => "ACCOUNT",
            .clientguid => "CLIENTGUID",
            .servicepath => "SERVICEPATH",
        };
    }
};

pub const ChannelPropInfo = struct {
    key: ChannelPropKey,
    max_value: usize,
    min_setter: AccessLevel,
    read_only: bool = false,
    secret: bool = false,
};

pub fn channelPropKey(raw: []const u8) ?ChannelPropKey {
    inline for (@typeInfo(ChannelPropKey).@"enum".fields) |field| {
        const key: ChannelPropKey = @field(ChannelPropKey, field.name);
        if (std.ascii.eqlIgnoreCase(raw, key.token())) return key;
    }
    return null;
}

pub fn channelPropInfo(raw: []const u8) ?ChannelPropInfo {
    const key = channelPropKey(raw) orelse return null;
    return switch (key) {
        .oid, .name, .creation => .{ .key = key, .max_value = 63, .min_setter = .server, .read_only = true },
        .language => .{ .key = key, .max_value = 31, .min_setter = .host },
        .ownerkey => .{ .key = key, .max_value = 31, .min_setter = .owner, .secret = true },
        .hostkey, .memberkey => .{ .key = key, .max_value = 31, .min_setter = .owner, .secret = true },
        .pics => .{ .key = key, .max_value = 255, .min_setter = .sysop_manager },
        .topic => .{ .key = key, .max_value = 160, .min_setter = .host },
        .subject => .{ .key = key, .max_value = 31, .min_setter = .host },
        .client, .onjoin, .onpart => .{ .key = key, .max_value = 255, .min_setter = .host },
        .lag => .{ .key = key, .max_value = 1, .min_setter = .owner },
        .account => .{ .key = key, .max_value = 31, .min_setter = .sysop_manager },
        .clientguid, .servicepath => .{ .key = key, .max_value = default_max_value, .min_setter = .owner },
    };
}

pub const EntryView = struct {
    entity: Entity,
    key: []const u8,
    value: []const u8,
    owner: []const u8,
    access: AccessLevel,
};

pub const QueryRequest = struct {
    entity: Entity,
    keys: []const u8,
};

pub const MutationRequest = struct {
    entity: Entity,
    key: []const u8,
    value: []const u8,
};

pub const KeyRequest = struct {
    entity: Entity,
    key: []const u8,
};

pub const Request = union(enum) {
    list: Entity,
    get: QueryRequest,
    set: MutationRequest,
    delete: KeyRequest,
};

pub fn PropStore(comptime params: Params) type {
    comptime {
        if (params.max_entities == 0) @compileError("PROP store needs at least one entity");
        if (params.max_props_per_entity == 0) @compileError("PROP store needs at least one property per entity");
        if (params.max_entity_id == 0) @compileError("PROP entity ids need storage");
        if (params.max_key == 0) @compileError("PROP keys need storage");
        if (params.max_value > ircx.MAX_PROP_VALUE) @compileError("PROP values exceed IRCX advertised limit");
        if (params.max_owner_bytes == 0) @compileError("PROP owner ids need storage");
    }

    return struct {
        const Self = @This();
        const max_entity_key = EntityKind.member.token().len + 1 + params.max_entity_id;

        allocator: std.mem.Allocator,
        entities: std.StringHashMap(EntityState),
        entity_count: usize = 0,

        const Entry = struct {
            key: []u8,
            value: []u8,
            owner: []u8,
            access: AccessLevel,

            fn deinit(self: Entry, allocator: std.mem.Allocator) void {
                allocator.free(self.key);
                allocator.free(self.value);
                allocator.free(self.owner);
            }
        };

        const EntityState = struct {
            entity: Entity,
            props: std.StringHashMap(Entry),
            prop_count: usize = 0,

            fn init(allocator: std.mem.Allocator, entity: Entity) EntityState {
                return .{
                    .entity = entity,
                    .props = std.StringHashMap(Entry).init(allocator),
                };
            }

            fn deinit(self: *EntityState, allocator: std.mem.Allocator) void {
                allocator.free(self.entity.id);
                var it = self.props.iterator();
                while (it.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    entry.value_ptr.deinit(allocator);
                }
                self.props.deinit();
                self.* = undefined;
            }
        };

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .entities = std.StringHashMap(EntityState).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.clear();
            self.entities.deinit();
            self.* = undefined;
        }

        pub fn clear(self: *Self) void {
            var it = self.entities.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.entities.clearRetainingCapacity();
            self.entity_count = 0;
        }

        /// Remove the channel entity and every member entity for `channel`, so a
        /// recreated same-named channel never inherits stale (possibly secret)
        /// properties. Scan-and-remove-one to avoid iterator invalidation.
        pub fn clearChannel(self: *Self, channel: []const u8) void {
            while (true) {
                var found: ?[]const u8 = null;
                var it = self.entities.iterator();
                while (it.next()) |entry| {
                    if (entityInChannel(entry.value_ptr.entity, channel)) {
                        found = entry.key_ptr.*;
                        break;
                    }
                }
                const key = found orelse break;
                if (self.entities.fetchRemove(key)) |kv| {
                    self.allocator.free(kv.key);
                    var state = kv.value;
                    state.deinit(self.allocator);
                    if (self.entity_count > 0) self.entity_count -= 1;
                } else break;
            }
        }

        fn entityInChannel(entity: Entity, channel: []const u8) bool {
            return switch (entity.kind) {
                .channel => std.ascii.eqlIgnoreCase(entity.id, channel),
                .member => blk: {
                    const split = std.mem.indexOfScalar(u8, entity.id, ':') orelse break :blk false;
                    break :blk std.ascii.eqlIgnoreCase(entity.id[0..split], channel);
                },
                .user => false,
            };
        }

        pub fn setProp(self: *Self, entity: Entity, key: []const u8, value: []const u8, setter: Setter) PropError!EntryView {
            try validateEntity(entity, params.max_entity_id);
            try validateKeyWithLimit(key, params.max_key);
            try validateOwner(setter.id, params.max_owner_bytes);
            try validateValueFor(entity, key, value, setter.access, params.max_value);

            var state = try self.getOrCreateEntity(entity);
            const existing = state.props.getEntry(key);
            if (existing == null and state.prop_count >= params.max_props_per_entity) return error.LimitReached;

            const value_copy = self.allocator.dupe(u8, value) catch return error.LimitReached;
            errdefer self.allocator.free(value_copy);
            const owner_copy = self.allocator.dupe(u8, setter.id) catch return error.LimitReached;
            errdefer self.allocator.free(owner_copy);

            if (existing) |entry| {
                self.allocator.free(entry.value_ptr.value);
                self.allocator.free(entry.value_ptr.owner);
                entry.value_ptr.value = value_copy;
                entry.value_ptr.owner = owner_copy;
                entry.value_ptr.access = setter.access;
                return view(state, entry.value_ptr);
            }

            const map_key = try makePropKey(self.allocator, key);
            errdefer self.allocator.free(map_key);
            const display_key = try makeDisplayKey(self.allocator, entity, key);
            errdefer self.allocator.free(display_key);

            const gop = state.props.getOrPut(map_key) catch return error.LimitReached;
            if (gop.found_existing) {
                self.allocator.free(map_key);
                self.allocator.free(display_key);
                self.allocator.free(gop.value_ptr.value);
                self.allocator.free(gop.value_ptr.owner);
                gop.value_ptr.value = value_copy;
                gop.value_ptr.owner = owner_copy;
                gop.value_ptr.access = setter.access;
                return view(state, gop.value_ptr);
            }

            gop.key_ptr.* = map_key;
            gop.value_ptr.* = .{
                .key = display_key,
                .value = value_copy,
                .owner = owner_copy,
                .access = setter.access,
            };
            state.prop_count += 1;
            return view(state, gop.value_ptr);
        }

        pub fn getProp(self: *const Self, entity: Entity, key: []const u8) PropError!EntryView {
            try validateEntity(entity, params.max_entity_id);
            try validateKeyWithLimit(key, params.max_key);

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            const state = self.entities.getPtr(entity_key) orelse return error.PropMissing;

            var prop_key_buf: [params.max_key]u8 = undefined;
            const prop_key = try writePropKey(&prop_key_buf, key, params.max_key);
            const entry = state.props.getPtr(prop_key) orelse return error.PropMissing;
            return view(state, entry);
        }

        pub fn deleteProp(self: *Self, entity: Entity, key: []const u8) PropError!void {
            try validateEntity(entity, params.max_entity_id);
            try validateKeyWithLimit(key, params.max_key);

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            var state = self.entities.getPtr(entity_key) orelse return error.PropMissing;

            var prop_key_buf: [params.max_key]u8 = undefined;
            const prop_key = try writePropKey(&prop_key_buf, key, params.max_key);
            const removed = state.props.fetchRemove(prop_key) orelse return error.PropMissing;
            self.allocator.free(removed.key);
            removed.value.deinit(self.allocator);
            state.prop_count -= 1;

            if (state.prop_count == 0) {
                const removed_entity = self.entities.fetchRemove(entity_key).?;
                self.allocator.free(removed_entity.key);
                var empty_state = removed_entity.value;
                empty_state.deinit(self.allocator);
                self.entity_count -= 1;
            }
        }

        pub fn listProps(self: *const Self, entity: Entity, out: []EntryView) PropError![]EntryView {
            try validateEntity(entity, params.max_entity_id);

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            const state = self.entities.getPtr(entity_key) orelse return out[0..0];
            if (state.prop_count > out.len) return error.OutputTooSmall;

            var count: usize = 0;
            var it = state.props.iterator();
            while (it.next()) |entry| {
                out[count] = view(state, entry.value_ptr);
                count += 1;
            }

            const listed = out[0..count];
            std.sort.insertion(EntryView, listed, {}, entryLessThan);
            return listed;
        }

        fn getOrCreateEntity(self: *Self, entity: Entity) PropError!*EntityState {
            var key_buf: [max_entity_key]u8 = undefined;
            const key = try writeEntityKey(&key_buf, entity, params.max_entity_id);
            if (self.entities.getPtr(key)) |state| return state;
            if (self.entity_count >= params.max_entities) return error.LimitReached;

            const map_key = self.allocator.dupe(u8, key) catch return error.LimitReached;
            errdefer self.allocator.free(map_key);
            const id_copy = self.allocator.dupe(u8, entity.id) catch return error.LimitReached;
            errdefer self.allocator.free(id_copy);

            const gop = self.entities.getOrPut(map_key) catch return error.LimitReached;
            if (gop.found_existing) {
                self.allocator.free(map_key);
                self.allocator.free(id_copy);
                return gop.value_ptr;
            }

            gop.key_ptr.* = map_key;
            gop.value_ptr.* = EntityState.init(self.allocator, .{ .kind = entity.kind, .id = id_copy });
            self.entity_count += 1;
            return gop.value_ptr;
        }

        fn view(state: *const EntityState, entry: *const Entry) EntryView {
            return .{
                .entity = state.entity,
                .key = entry.key,
                .value = entry.value,
                .owner = entry.owner,
                .access = entry.access,
            };
        }
    };
}

pub const DefaultStore = PropStore(.{});

pub fn parseLine(line: []const u8) PropError!Request {
    return parseLineBounded(.{}, line);
}

pub fn parseLineBounded(comptime params: Params, line: []const u8) PropError!Request {
    const parsed = try irc_line.parseLine(line);
    if (!std.ascii.eqlIgnoreCase(parsed.command, "PROP")) return error.InvalidCommand;
    return parseParamsBounded(params, parsed.paramSlice(), parsed.trailing != null);
}

pub fn parseParamsBounded(comptime params: Params, params_slice: []const []const u8, had_trailing: bool) PropError!Request {
    if (params_slice.len == 0) return error.NeedMoreParams;
    if (params_slice.len > 3) return error.TooManyParams;

    const entity = try Entity.fromId(params_slice[0]);
    try validateEntity(entity, params.max_entity_id);

    if (params_slice.len == 1) return .{ .list = entity };

    const key = params_slice[1];
    try validateKeyList(key, params.max_key, params.max_request_keys);

    if (params_slice.len == 2) return .{ .get = .{ .entity = entity, .keys = key } };
    if (std.mem.indexOfScalar(u8, key, ',') != null) return error.InvalidKey;

    const value = params_slice[2];
    if (had_trailing and value.len == 0) {
        return .{ .delete = .{ .entity = entity, .key = key } };
    }

    try validateValue(value, params.max_value);
    return .{ .set = .{ .entity = entity, .key = key, .value = value } };
}

pub fn buildPropMessage(entity: Entity, key: []const u8, value: []const u8, out: []u8) PropError![]const u8 {
    try validateEntity(entity, default_max_entity_id);
    try validateKeyWithLimit(key, default_max_key);
    try validateValue(value, default_max_value);
    return std.fmt.bufPrint(out, "PROP {s} {s} :{s}", .{ entity.id, key, value }) catch error.OutputTooSmall;
}

pub fn buildPropListReply(server: []const u8, nick: []const u8, entry: EntryView, out: []u8) PropError![]const u8 {
    try validateReplyAtom(server);
    try validateReplyAtom(nick);
    return std.fmt.bufPrint(out, ":{s} 818 {s} {s} {s} :{s}", .{
        server,
        nick,
        entry.entity.id,
        entry.key,
        entry.value,
    }) catch error.OutputTooSmall;
}

pub fn buildPropEndReply(server: []const u8, nick: []const u8, entity: Entity, out: []u8) PropError![]const u8 {
    try validateReplyAtom(server);
    try validateReplyAtom(nick);
    try validateEntity(entity, default_max_entity_id);
    return std.fmt.bufPrint(out, ":{s} 819 {s} {s} :End of properties", .{ server, nick, entity.id }) catch error.OutputTooSmall;
}

fn validateEntity(entity: Entity, max_entity_id: usize) PropError!void {
    if (entity.id.len == 0 or entity.id.len > max_entity_id) return error.InvalidEntity;
    try validateSafeText(entity.id, error.InvalidEntity);
    for (entity.id) |byte| {
        if (byte <= 0x20 or byte == ',' or byte == 0x7f) return error.InvalidEntity;
    }

    switch (entity.kind) {
        .channel => switch (entity.id[0]) {
            '#', '&', '+', '%' => {},
            else => return error.InvalidEntity,
        },
        .user => if (std.mem.indexOfScalar(u8, entity.id, ':') != null) return error.InvalidEntity,
        .member => {
            const split = std.mem.indexOfScalar(u8, entity.id, ':') orelse return error.InvalidEntity;
            if (split == 0 or split + 1 >= entity.id.len) return error.InvalidEntity;
        },
    }
}

fn validateKeyList(raw: []const u8, max_key: usize, max_request_keys: usize) PropError!void {
    if (raw.len == 0) return error.InvalidKey;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |key| {
        count += 1;
        if (count > max_request_keys) return error.TooManyParams;
        try validateKeyWithLimit(key, max_key);
    }
}

fn validateKeyWithLimit(key: []const u8, max_key: usize) PropError!void {
    if (key.len == 0 or key.len > max_key) return error.InvalidKey;
    for (key) |byte| {
        switch (byte) {
            'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.' => {},
            else => return error.InvalidKey,
        }
    }
}

fn validateValueFor(entity: Entity, key: []const u8, value: []const u8, access: AccessLevel, max_value: usize) PropError!void {
    var limit = max_value;
    if (entity.kind == .channel) {
        if (channelPropInfo(key)) |info| {
            if (info.read_only) return error.ReadOnlyProperty;
            if (!access.allows(info.min_setter)) return error.AccessDenied;
            limit = @min(limit, info.max_value);
        } else if (!access.allows(.host)) {
            return error.AccessDenied;
        }
    }
    try validateValue(value, limit);
}

fn validateValue(value: []const u8, max_value: usize) PropError!void {
    if (value.len > max_value) return error.InvalidValue;
    try validateSafeText(value, error.InvalidValue);
}

fn validateOwner(owner: []const u8, max_owner_bytes: usize) PropError!void {
    if (owner.len == 0 or owner.len > max_owner_bytes) return error.InvalidOwner;
    for (owner) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == ',' or byte == ':') return error.InvalidOwner;
    }
}

fn validateReplyAtom(raw: []const u8) PropError!void {
    if (raw.len == 0) return error.InvalidEntity;
    try validateSafeText(raw, error.InvalidEntity);
    for (raw) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return error.InvalidEntity;
    }
}

fn validateSafeText(bytes: []const u8, comptime err: PropError) PropError!void {
    for (bytes) |byte| {
        switch (byte) {
            0, '\r', '\n' => return err,
            1...8, 11, 12, 14...31, 127 => return err,
            else => {},
        }
    }
}

fn makePropKey(allocator: std.mem.Allocator, key: []const u8) PropError![]u8 {
    const out = allocator.alloc(u8, key.len) catch return error.LimitReached;
    errdefer allocator.free(out);
    _ = try writePropKey(out, key, key.len);
    return out;
}

fn makeDisplayKey(allocator: std.mem.Allocator, entity: Entity, key: []const u8) PropError![]u8 {
    if (entity.kind == .channel) {
        if (channelPropKey(key)) |known| return allocator.dupe(u8, known.token()) catch return error.LimitReached;
    }
    return allocator.dupe(u8, key) catch return error.LimitReached;
}

fn writePropKey(out: []u8, key: []const u8, max_key: usize) PropError![]const u8 {
    try validateKeyWithLimit(key, max_key);
    if (out.len < key.len) return error.OutputTooSmall;
    for (key, 0..) |byte, index| out[index] = std.ascii.toLower(byte);
    return out[0..key.len];
}

fn writeEntityKey(out: []u8, entity: Entity, max_entity_id: usize) PropError![]const u8 {
    try validateEntity(entity, max_entity_id);
    const prefix = entity.kind.token();
    const len = prefix.len + 1 + entity.id.len;
    if (out.len < len) return error.OutputTooSmall;
    @memcpy(out[0..prefix.len], prefix);
    out[prefix.len] = 0x1f;
    for (entity.id, 0..) |byte, index| out[prefix.len + 1 + index] = std.ascii.toLower(byte);
    return out[0..len];
}

fn entryLessThan(_: void, lhs: EntryView, rhs: EntryView) bool {
    return std.mem.lessThan(u8, lhs.key, rhs.key);
}

test "set get overwrite delete and list properties" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const entity = try Entity.fromId("#Mizuchi");
    const setter = Setter{ .id = "alice", .access = .owner };

    const first = try store.setProp(entity, "topic", "first", setter);
    try std.testing.expectEqualStrings("TOPIC", first.key);
    try std.testing.expectEqualStrings("first", first.value);
    try std.testing.expectEqualStrings("alice", first.owner);
    try std.testing.expectEqual(AccessLevel.owner, first.access);

    _ = try store.setProp(entity, "TOPIC", "second", .{ .id = "bob", .access = .owner });
    const got = try store.getProp(entity, "topic");
    try std.testing.expectEqualStrings("second", got.value);
    try std.testing.expectEqualStrings("bob", got.owner);

    _ = try store.setProp(entity, "SUBJECT", "zig", setter);
    var out: [4]EntryView = undefined;
    const listed = try store.listProps(try Entity.fromId("#mizuchi"), &out);
    try std.testing.expectEqual(@as(usize, 2), listed.len);
    try std.testing.expectEqualStrings("SUBJECT", listed[0].key);
    try std.testing.expectEqualStrings("TOPIC", listed[1].key);

    try store.deleteProp(entity, "topic");
    try std.testing.expectError(error.PropMissing, store.getProp(entity, "topic"));
    try std.testing.expectEqual(@as(usize, 1), (try store.listProps(entity, &out)).len);
    try store.deleteProp(entity, "subject");
    try std.testing.expectEqual(@as(usize, 0), (try store.listProps(entity, &out)).len);
}

test "parse each PROP request form" {
    const list = try parseLine("PROP #chan");
    try std.testing.expectEqual(Request.list, @as(std.meta.Tag(Request), list));
    try std.testing.expectEqualStrings("#chan", list.list.id);

    const get = try parseLine("PROP #chan TOPIC,ONJOIN");
    try std.testing.expectEqual(Request.get, @as(std.meta.Tag(Request), get));
    try std.testing.expectEqualStrings("TOPIC,ONJOIN", get.get.keys);

    const set = try parseLine("PROP #chan TOPIC :hello world");
    try std.testing.expectEqual(Request.set, @as(std.meta.Tag(Request), set));
    try std.testing.expectEqualStrings("hello world", set.set.value);

    const del = try parseLine("PROP #chan TOPIC :");
    try std.testing.expectEqual(Request.delete, @as(std.meta.Tag(Request), del));
    try std.testing.expectEqualStrings("TOPIC", del.delete.key);

    try std.testing.expectError(error.InvalidCommand, parseLine("PRIVMSG #chan :no"));
    try std.testing.expectError(error.NeedMoreParams, parseLine("PROP"));
    try std.testing.expectError(error.TooManyParams, parseLine("PROP #c A B C"));
}

test "limits and built-in channel property metadata are enforced" {
    const Tiny = PropStore(.{
        .max_entities = 1,
        .max_props_per_entity = 1,
        .max_entity_id = 8,
        .max_key = 8,
        .max_value = 8,
        .max_owner_bytes = 8,
    });
    var store = Tiny.init(std.testing.allocator);
    defer store.deinit();

    const entity = try Entity.fromId("#c");
    _ = try store.setProp(entity, "custom", "12345678", .{ .id = "owner", .access = .host });
    try std.testing.expectError(error.LimitReached, store.setProp(entity, "other", "1", .{ .id = "owner", .access = .host }));
    try std.testing.expectError(error.LimitReached, store.setProp(try Entity.fromId("#d"), "custom", "1", .{ .id = "owner", .access = .host }));
    try std.testing.expectError(error.InvalidValue, store.setProp(entity, "custom", "123456789", .{ .id = "owner", .access = .host }));
    try std.testing.expectError(error.InvalidOwner, store.setProp(entity, "custom", "1", .{ .id = "bad owner", .access = .host }));

    try std.testing.expect(channelPropKey("OWNERKEY").? == .ownerkey);
    try std.testing.expect((channelPropInfo("OWNERKEY").?).secret);
    try std.testing.expectError(error.ReadOnlyProperty, store.setProp(entity, "OID", "1", .{ .id = "server", .access = .server }));
    try std.testing.expectError(error.AccessDenied, store.setProp(entity, "PICS", "safe", .{ .id = "owner", .access = .owner }));
}

test "reply builders and no-leak clear path" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const entity = try Entity.fromId("#reply");
    const entry = try store.setProp(entity, "TOPIC", "hello", .{ .id = "oper", .access = .owner });

    var out: [160]u8 = undefined;
    try std.testing.expectEqualStrings("PROP #reply TOPIC :hello", try buildPropMessage(entity, entry.key, entry.value, &out));
    try std.testing.expectEqualStrings(":irc.example 818 nick #reply TOPIC :hello", try buildPropListReply("irc.example", "nick", entry, &out));
    try std.testing.expectEqualStrings(":irc.example 819 nick #reply :End of properties", try buildPropEndReply("irc.example", "nick", entity, &out));
    try std.testing.expectError(error.OutputTooSmall, buildPropListReply("irc.example", "nick", entry, out[0..8]));

    store.clear();
    _ = try store.setProp(try Entity.fromId("nick"), "away", "no", .{ .id = "nick", .access = .user });
}
