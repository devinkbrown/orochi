// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

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
pub const user_profile_max_value: usize = 200;

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
        // Member entities use `<channel>:<nick>` and therefore also begin with
        // a channel sigil. Classify the delimiter before the leading sigil.
        const kind: EntityKind = if (std.mem.indexOfScalar(u8, id, ':') != null) .member else if (isChannelEntityId(id)) .channel else .user;
        const entity = Entity{ .kind = kind, .id = id };
        try validateEntity(entity, default_max_entity_id);
        return entity;
    }
};

fn isChannelEntityId(id: []const u8) bool {
    return switch (id[0]) {
        '#', '&' => true,
        '%' => id.len >= 2 and (id[1] == '#' or id[1] == '&'),
        else => false,
    };
}

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
    membercount,
    memberlimit,
    language,
    founderkey,
    ownerkey,
    hostkey,
    voicekey,
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
    no_ai,
    local_only,
    server_ai_ok,
    history_policy,
    encryption_policy,

    pub fn token(self: ChannelPropKey) []const u8 {
        return switch (self) {
            .oid => "OID",
            .name => "NAME",
            .creation => "CREATION",
            .membercount => "MEMBERCOUNT",
            .memberlimit => "MEMBERLIMIT",
            .language => "LANGUAGE",
            .founderkey => "FOUNDERKEY",
            .ownerkey => "OWNERKEY",
            .hostkey => "HOSTKEY",
            .voicekey => "VOICEKEY",
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
            .no_ai => "no-ai",
            .local_only => "local-only",
            .server_ai_ok => "server-ai-ok",
            .history_policy => "history-policy",
            .encryption_policy => "encryption-policy",
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
    inline for (@typeInfo(ChannelPropKey).@"enum".field_names) |field_name| {
        const key: ChannelPropKey = @field(ChannelPropKey, field_name);
        if (std.ascii.eqlIgnoreCase(raw, key.token())) return key;
    }
    return null;
}

pub fn channelPropInfo(raw: []const u8) ?ChannelPropInfo {
    const key = channelPropKey(raw) orelse return null;
    return switch (key) {
        .oid, .name, .creation => .{ .key = key, .max_value = 63, .min_setter = .server, .read_only = true },
        // MEMBERCOUNT is a live computed value; never client-writable.
        .membercount => .{ .key = key, .max_value = 20, .min_setter = .server, .read_only = true },
        // MEMBERLIMIT mirrors channel mode +l; host may set it (the daemon links
        // the write to the MODE change before the generic store is consulted).
        .memberlimit => .{ .key = key, .max_value = 20, .min_setter = .host },
        .language => .{ .key = key, .max_value = 31, .min_setter = .host },
        // FOUNDERKEY grants the top FOUNDER tier on join; like OWNERKEY it is
        // owner-set (the prop AccessLevel ladder tops out at owner — founder is a
        // membership rank, not a setter tier) and its value is secret.
        .founderkey => .{ .key = key, .max_value = 31, .min_setter = .owner, .secret = true },
        .ownerkey => .{ .key = key, .max_value = 31, .min_setter = .owner, .secret = true },
        .hostkey, .memberkey => .{ .key = key, .max_value = 31, .min_setter = .owner, .secret = true },
        // VOICEKEY is settable by operators and above (op-tier), unlike the
        // owner-set OWNER/HOST/MEMBER keys; its value is still secret.
        .voicekey => .{ .key = key, .max_value = 31, .min_setter = .host, .secret = true },
        .pics => .{ .key = key, .max_value = 255, .min_setter = .sysop_manager },
        .topic => .{ .key = key, .max_value = 160, .min_setter = .host },
        .subject => .{ .key = key, .max_value = 31, .min_setter = .host },
        .client, .onjoin, .onpart => .{ .key = key, .max_value = 255, .min_setter = .host },
        .lag => .{ .key = key, .max_value = 1, .min_setter = .owner },
        .account => .{ .key = key, .max_value = 31, .min_setter = .sysop_manager },
        .clientguid, .servicepath => .{ .key = key, .max_value = default_max_value, .min_setter = .owner },
        // AI policy flags are intentionally small, public channel props: later
        // AI/plugin/MCP paths can enforce them without inventing a second policy
        // store. The daemon validates values as boolean tokens before storage.
        .no_ai, .local_only, .server_ai_ok => .{ .key = key, .max_value = 1, .min_setter = .host },
        .history_policy => .{ .key = key, .max_value = 16, .min_setter = .host },
        .encryption_policy => .{ .key = key, .max_value = 16, .min_setter = .host },
    };
}

pub const UserProfilePropKey = enum {
    url,
    gender,
    picture,
    bio,
    email,

    pub fn token(self: UserProfilePropKey) []const u8 {
        return switch (self) {
            .url => "URL",
            .gender => "GENDER",
            .picture => "PICTURE",
            .bio => "BIO",
            .email => "EMAIL",
        };
    }
};

pub const UserProfilePropInfo = struct {
    key: UserProfilePropKey,
    max_value: usize,
};

pub fn userProfilePropKey(raw: []const u8) ?UserProfilePropKey {
    inline for (@typeInfo(UserProfilePropKey).@"enum".field_names) |field_name| {
        const key: UserProfilePropKey = @field(UserProfilePropKey, field_name);
        if (std.ascii.eqlIgnoreCase(raw, key.token())) return key;
    }
    return null;
}

pub fn userProfilePropInfo(raw: []const u8) ?UserProfilePropInfo {
    const key = userProfilePropKey(raw) orelse return null;
    return .{ .key = key, .max_value = user_profile_max_value };
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

        /// Stable, ticket-owned fact preview used by the daemon to prepare the
        /// matching mesh-clock transaction from the exact store image that will
        /// commit. Every slice owns independent bytes; none aliases the live
        /// store, the detached replacement state, or another fact.
        pub const PreparedPropFact = struct {
            entity: Entity,
            key: []const u8,
            value: []const u8,
            owner: []const u8,
            access: AccessLevel,

            fn deinit(self: *PreparedPropFact, allocator: std.mem.Allocator) void {
                allocator.free(@constCast(self.entity.id));
                allocator.free(@constCast(self.key));
                allocator.free(@constCast(self.value));
                allocator.free(@constCast(self.owner));
                self.* = undefined;
            }
        };

        /// Allocation-complete public-channel clone plan. The ticket is
        /// logically non-copyable: retain one mutable value and call commit,
        /// abort, or deinit exactly as with the daemon's other prepared tickets.
        /// Replacement/purge previews remain stable only while state=prepared.
        pub const PreparedPublicChannelClone = struct {
            const State = enum { prepared, committed, aborted };

            store: *Self,
            /// Independently-owned normalized lookup keys for every destination
            /// channel/member entity that commit will remove.
            purge_entity_keys: [][]u8,
            /// Independently-owned stable views for clock/tombstone preparation.
            replacement_facts: []PreparedPropFact,
            purge_facts: []PreparedPropFact,
            /// Detached destination channel state and its distinct outer map key.
            /// Null means the source has no public properties, so commit is an
            /// exact destination clear with no replacement entity.
            staged_outer_key: ?[]u8,
            staged_state: ?EntityState,
            state: State = .prepared,

            pub fn replacementFacts(self: *const PreparedPublicChannelClone) []const PreparedPropFact {
                std.debug.assert(self.state == .prepared);
                if (self.state != .prepared) return &.{};
                return self.replacement_facts;
            }

            pub fn purgedFacts(self: *const PreparedPublicChannelClone) []const PreparedPropFact {
                std.debug.assert(self.state == .prepared);
                if (self.state != .prepared) return &.{};
                return self.purge_facts;
            }

            /// Publish the complete prepared image without allocating. Callers
            /// serialize prepare->commit under the daemon's World write lock, so
            /// every copied purge key is guaranteed to remain present here.
            pub fn commit(self: *PreparedPublicChannelClone) void {
                if (self.state != .prepared) return;
                for (self.purge_entity_keys) |lookup_key| {
                    const removed = self.store.entities.fetchRemove(lookup_key) orelse unreachable;
                    self.store.allocator.free(removed.key);
                    var removed_state = removed.value;
                    removed_state.deinit(self.store.allocator);
                    std.debug.assert(self.store.entity_count != 0);
                    self.store.entity_count -= 1;
                }
                if (self.staged_outer_key) |outer_key| {
                    const staged = self.staged_state orelse unreachable;
                    self.store.entities.putAssumeCapacityNoClobber(outer_key, staged);
                    self.store.entity_count += 1;
                    self.staged_outer_key = null;
                    self.staged_state = null;
                }
                self.destroyPlanOwned();
                self.state = .committed;
            }

            /// Discard the detached image. Idempotent before or after another
            /// lifecycle method, so `defer ticket.deinit()` is always safe.
            pub fn abort(self: *PreparedPublicChannelClone) void {
                if (self.state != .prepared) return;
                if (self.staged_state) |*staged| staged.deinit(self.store.allocator);
                self.staged_state = null;
                if (self.staged_outer_key) |key| self.store.allocator.free(key);
                self.staged_outer_key = null;
                self.destroyPlanOwned();
                self.state = .aborted;
            }

            pub fn deinit(self: *PreparedPublicChannelClone) void {
                self.abort();
            }

            fn destroyPlanOwned(self: *PreparedPublicChannelClone) void {
                for (self.purge_entity_keys) |key| self.store.allocator.free(key);
                self.store.allocator.free(self.purge_entity_keys);
                self.purge_entity_keys = undefined;
                for (self.replacement_facts) |*fact| fact.deinit(self.store.allocator);
                self.store.allocator.free(self.replacement_facts);
                self.replacement_facts = undefined;
                for (self.purge_facts) |*fact| fact.deinit(self.store.allocator);
                self.store.allocator.free(self.purge_facts);
                self.purge_facts = undefined;
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

        /// Prepare an exact public-PROP image for a newly-created channel clone.
        /// Public source channel properties are deep-copied; secret source keys
        /// are deliberately excluded. Commit also removes every stale destination
        /// channel and `channel:nick` member entity, matching clearChannel's new-
        /// incarnation semantics. No live state changes until commit.
        pub fn preparePublicChannelClone(
            self: *Self,
            source_channel: []const u8,
            destination_channel: []const u8,
        ) PropError!PreparedPublicChannelClone {
            const source_entity = Entity{ .kind = .channel, .id = source_channel };
            const destination_entity = Entity{ .kind = .channel, .id = destination_channel };
            try validateEntity(source_entity, params.max_entity_id);
            try validateEntity(destination_entity, params.max_entity_id);
            if (!isChannelEntityId(source_channel) or !isChannelEntityId(destination_channel))
                return error.InvalidEntity;
            if (std.ascii.eqlIgnoreCase(source_channel, destination_channel))
                return error.InvalidEntity;

            var source_key_buf: [max_entity_key]u8 = undefined;
            const source_key = try writeEntityKey(&source_key_buf, source_entity, params.max_entity_id);
            const source_state = self.entities.getPtr(source_key);

            var replacement_count: usize = 0;
            if (source_state) |state| {
                var props_it = state.props.iterator();
                while (props_it.next()) |entry| {
                    if (!isSecretChannelProp(source_entity, entry.value_ptr.key))
                        replacement_count = std.math.add(usize, replacement_count, 1) catch return error.LimitReached;
                }
            }

            var purge_entity_count: usize = 0;
            var purge_fact_count: usize = 0;
            var entity_it = self.entities.iterator();
            while (entity_it.next()) |entry| {
                if (!entityInChannel(entry.value_ptr.entity, destination_channel)) continue;
                purge_entity_count = std.math.add(usize, purge_entity_count, 1) catch return error.LimitReached;
                purge_fact_count = std.math.add(usize, purge_fact_count, entry.value_ptr.prop_count) catch return error.LimitReached;
            }
            std.debug.assert(purge_entity_count <= self.entity_count);
            const retained_count = self.entity_count - purge_entity_count;
            if (replacement_count != 0 and retained_count >= params.max_entities)
                return error.LimitReached;

            const purge_entity_keys = self.allocator.alloc([]u8, purge_entity_count) catch return error.LimitReached;
            var purge_entity_keys_init: usize = 0;
            errdefer {
                for (purge_entity_keys[0..purge_entity_keys_init]) |key| self.allocator.free(key);
                self.allocator.free(purge_entity_keys);
            }
            const replacement_facts = self.allocator.alloc(PreparedPropFact, replacement_count) catch return error.LimitReached;
            var replacement_facts_init: usize = 0;
            errdefer {
                for (replacement_facts[0..replacement_facts_init]) |*fact| fact.deinit(self.allocator);
                self.allocator.free(replacement_facts);
            }
            const purge_facts = self.allocator.alloc(PreparedPropFact, purge_fact_count) catch return error.LimitReached;
            var purge_facts_init: usize = 0;
            errdefer {
                for (purge_facts[0..purge_facts_init]) |*fact| fact.deinit(self.allocator);
                self.allocator.free(purge_facts);
            }

            // Snapshot all purge selectors/facts before any outer-map capacity
            // reservation can rehash and invalidate iterator entry pointers.
            entity_it = self.entities.iterator();
            while (entity_it.next()) |entry| {
                if (!entityInChannel(entry.value_ptr.entity, destination_channel)) continue;
                purge_entity_keys[purge_entity_keys_init] = self.allocator.dupe(u8, entry.key_ptr.*) catch return error.LimitReached;
                purge_entity_keys_init += 1;
                var props_it = entry.value_ptr.props.iterator();
                while (props_it.next()) |prop_entry| {
                    purge_facts[purge_facts_init] = try clonePreparedPropFact(
                        self.allocator,
                        entry.value_ptr.entity,
                        prop_entry.value_ptr,
                    );
                    purge_facts_init += 1;
                }
            }
            std.debug.assert(purge_entity_keys_init == purge_entity_keys.len);
            std.debug.assert(purge_facts_init == purge_facts.len);

            // Build stable replacement previews separately from the detached
            // EntityState so clock preparation cannot alias bytes commit moves.
            if (source_state) |state| {
                var props_it = state.props.iterator();
                while (props_it.next()) |entry| {
                    if (isSecretChannelProp(source_entity, entry.value_ptr.key)) continue;
                    replacement_facts[replacement_facts_init] = try clonePreparedPropFact(
                        self.allocator,
                        destination_entity,
                        entry.value_ptr,
                    );
                    replacement_facts_init += 1;
                }
            }
            std.debug.assert(replacement_facts_init == replacement_facts.len);
            std.mem.sort(PreparedPropFact, replacement_facts, {}, preparedPropFactLessThan);
            std.mem.sort(PreparedPropFact, purge_facts, {}, preparedPropFactLessThan);

            var staged_outer_key: ?[]u8 = null;
            errdefer if (staged_outer_key) |key| self.allocator.free(key);
            var staged_state: ?EntityState = null;
            errdefer if (staged_state) |*state| state.deinit(self.allocator);
            if (replacement_count != 0) {
                var destination_key_buf: [max_entity_key]u8 = undefined;
                const destination_key = try writeEntityKey(
                    &destination_key_buf,
                    destination_entity,
                    params.max_entity_id,
                );
                staged_outer_key = self.allocator.dupe(u8, destination_key) catch return error.LimitReached;
                const destination_id = self.allocator.dupe(u8, destination_channel) catch return error.LimitReached;
                staged_state = EntityState.init(self.allocator, .{ .kind = .channel, .id = destination_id });
                const state = &staged_state.?;
                if (source_state) |source| {
                    var props_it = source.props.iterator();
                    while (props_it.next()) |entry| {
                        if (isSecretChannelProp(source_entity, entry.value_ptr.key)) continue;
                        var cloned = try clonePreparedEntry(self.allocator, entry.key_ptr.*, entry.value_ptr);
                        state.props.put(cloned.normalized_key, cloned.entry) catch {
                            self.allocator.free(cloned.normalized_key);
                            cloned.entry.deinit(self.allocator);
                            return error.LimitReached;
                        };
                        state.prop_count += 1;
                    }
                }
                std.debug.assert(state.prop_count == replacement_count);

                // The detached source image and every lookup/preview byte are now
                // owned. Only now may the live outer map rehash.
                if (purge_entity_count == 0)
                    self.entities.ensureUnusedCapacity(1) catch return error.LimitReached;
            }

            const out = PreparedPublicChannelClone{
                .store = self,
                .purge_entity_keys = purge_entity_keys,
                .replacement_facts = replacement_facts,
                .purge_facts = purge_facts,
                .staged_outer_key = staged_outer_key,
                .staged_state = staged_state,
            };
            staged_outer_key = null;
            staged_state = null;
            purge_entity_keys_init = 0;
            replacement_facts_init = 0;
            purge_facts_init = 0;
            return out;
        }

        fn clonePreparedPropFact(
            allocator: std.mem.Allocator,
            entity: Entity,
            entry: *const Entry,
        ) PropError!PreparedPropFact {
            const entity_id = allocator.dupe(u8, entity.id) catch return error.LimitReached;
            errdefer allocator.free(entity_id);
            const key = allocator.dupe(u8, entry.key) catch return error.LimitReached;
            errdefer allocator.free(key);
            const value = allocator.dupe(u8, entry.value) catch return error.LimitReached;
            errdefer allocator.free(value);
            const owner = allocator.dupe(u8, entry.owner) catch return error.LimitReached;
            return .{
                .entity = .{ .kind = entity.kind, .id = entity_id },
                .key = key,
                .value = value,
                .owner = owner,
                .access = entry.access,
            };
        }

        fn clonePreparedEntry(
            allocator: std.mem.Allocator,
            normalized_key_source: []const u8,
            entry: *const Entry,
        ) PropError!struct { normalized_key: []u8, entry: Entry } {
            const normalized_key = allocator.dupe(u8, normalized_key_source) catch return error.LimitReached;
            errdefer allocator.free(normalized_key);
            const display_key = allocator.dupe(u8, entry.key) catch return error.LimitReached;
            errdefer allocator.free(display_key);
            const value = allocator.dupe(u8, entry.value) catch return error.LimitReached;
            errdefer allocator.free(value);
            const owner = allocator.dupe(u8, entry.owner) catch return error.LimitReached;
            return .{
                .normalized_key = normalized_key,
                .entry = .{
                    .key = display_key,
                    .value = value,
                    .owner = owner,
                    .access = entry.access,
                },
            };
        }

        fn preparedPropFactLessThan(_: void, lhs: PreparedPropFact, rhs: PreparedPropFact) bool {
            if (lhs.entity.kind != rhs.entity.kind)
                return @intFromEnum(lhs.entity.kind) < @intFromEnum(rhs.entity.kind);
            const entity_order = std.mem.order(u8, lhs.entity.id, rhs.entity.id);
            if (entity_order != .eq) return entity_order == .lt;
            const key_order = std.mem.order(u8, lhs.key, rhs.key);
            if (key_order != .eq) return key_order == .lt;
            const value_order = std.mem.order(u8, lhs.value, rhs.value);
            if (value_order != .eq) return value_order == .lt;
            const owner_order = std.mem.order(u8, lhs.owner, rhs.owner);
            if (owner_order != .eq) return owner_order == .lt;
            return @intFromEnum(lhs.access) < @intFromEnum(rhs.access);
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
            return self.getPropInternal(entity, key, false);
        }

        pub fn getPropRaw(self: *const Self, entity: Entity, key: []const u8) PropError!EntryView {
            return self.getPropInternal(entity, key, true);
        }

        fn getPropInternal(self: *const Self, entity: Entity, key: []const u8, include_secret: bool) PropError!EntryView {
            try validateEntity(entity, params.max_entity_id);
            try validateKeyWithLimit(key, params.max_key);

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            const state = self.entities.getPtr(entity_key) orelse return error.PropMissing;

            var prop_key_buf: [params.max_key]u8 = undefined;
            const prop_key = try writePropKey(&prop_key_buf, key, params.max_key);
            const entry = state.props.getPtr(prop_key) orelse return error.PropMissing;
            if (!include_secret and isSecretChannelProp(entity, entry.key)) return error.PropMissing;
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

        pub fn clearEntity(self: *Self, entity: Entity) PropError!void {
            try validateEntity(entity, params.max_entity_id);

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            const removed_entity = self.entities.fetchRemove(entity_key) orelse return;
            self.allocator.free(removed_entity.key);
            var state = removed_entity.value;
            state.deinit(self.allocator);
            if (self.entity_count > 0) self.entity_count -= 1;
        }

        /// List an entity's props, OMITTING secret channel keys. Use this for any
        /// untrusted/unauthenticated enumeration — secret values never appear.
        pub fn listProps(self: *const Self, entity: Entity, out: []EntryView) PropError![]EntryView {
            return self.listPropsInternal(entity, out, false);
        }

        /// List an entity's props INCLUDING secret channel keys. Callers MUST apply
        /// their own per-recipient visibility gate to each returned secret entry
        /// (the daemon's `maySeeSecretKey`); the store cannot know membership rank.
        pub fn listPropsRaw(self: *const Self, entity: Entity, out: []EntryView) PropError![]EntryView {
            return self.listPropsInternal(entity, out, true);
        }

        fn listPropsInternal(self: *const Self, entity: Entity, out: []EntryView, include_secret: bool) PropError![]EntryView {
            try validateEntity(entity, params.max_entity_id);

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            const state = self.entities.getPtr(entity_key) orelse return out[0..0];

            var count: usize = 0;
            var it = state.props.iterator();
            while (it.next()) |entry| {
                if (!include_secret and isSecretChannelProp(entity, entry.value_ptr.key)) continue;
                if (count >= out.len) return error.OutputTooSmall;
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
    if (params_slice.len > 4) return error.TooManyParams;

    const entity = try Entity.fromId(params_slice[0]);
    try validateEntity(entity, params.max_entity_id);

    if (params_slice.len == 1) return .{ .list = entity };

    if (std.ascii.eqlIgnoreCase(params_slice[1], "CLEAR")) {
        if (params_slice.len != 2) return error.TooManyParams;
        return .{ .delete = .{ .entity = entity, .key = "" } };
    }

    if (std.ascii.eqlIgnoreCase(params_slice[1], "GET")) {
        if (params_slice.len < 3) return error.NeedMoreParams;
        if (params_slice.len > 3) return error.TooManyParams;
        const keys = params_slice[2];
        try validateKeyList(keys, params.max_key, params.max_request_keys);
        return .{ .get = .{ .entity = entity, .keys = keys } };
    }

    if (std.ascii.eqlIgnoreCase(params_slice[1], "SET")) {
        if (params_slice.len < 3) return error.NeedMoreParams;
        const key = params_slice[2];
        try validateKeyWithLimit(key, params.max_key);
        if (std.mem.indexOfScalar(u8, key, ',') != null) return error.InvalidKey;
        if (params_slice.len == 3) return .{ .delete = .{ .entity = entity, .key = key } };

        const value = params_slice[3];
        if (had_trailing and value.len == 0) {
            return .{ .delete = .{ .entity = entity, .key = key } };
        }

        try validateValue(value, params.max_value);
        return .{ .set = .{ .entity = entity, .key = key, .value = value } };
    }

    if (params_slice.len > 3) return error.TooManyParams;

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
        .channel => {
            if (std.mem.indexOfScalar(u8, entity.id, ':') != null) return error.InvalidEntity;
            switch (entity.id[0]) {
                '#', '&', '+', '%' => {},
                else => return error.InvalidEntity,
            }
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
    } else if (entity.kind == .user) {
        if (userProfilePropInfo(key)) |info| {
            limit = @min(limit, info.max_value);
        }
    }
    try validateValue(value, limit);
}

fn isSecretChannelProp(entity: Entity, key: []const u8) bool {
    if (entity.kind != .channel) return false;
    const info = channelPropInfo(key) orelse return false;
    return info.secret;
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

    const entity = try Entity.fromId("#Orochi");
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
    const listed = try store.listProps(try Entity.fromId("#orochi"), &out);
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

test "parse IRCX PROP verb request forms" {
    const clear = try parseLine("PROP #chan CLEAR");
    try std.testing.expectEqual(Request.delete, @as(std.meta.Tag(Request), clear));
    try std.testing.expectEqualStrings("#chan", clear.delete.entity.id);
    try std.testing.expectEqualStrings("", clear.delete.key);

    const get = try parseLine("PROP #chan GET TOPIC,NAME");
    try std.testing.expectEqual(Request.get, @as(std.meta.Tag(Request), get));
    try std.testing.expectEqualStrings("TOPIC,NAME", get.get.keys);

    const set = try parseLine("PROP #chan SET TOPIC :hello world");
    try std.testing.expectEqual(Request.set, @as(std.meta.Tag(Request), set));
    try std.testing.expectEqualStrings("TOPIC", set.set.key);
    try std.testing.expectEqualStrings("hello world", set.set.value);

    const del = try parseLine("PROP #chan SET TOPIC :");
    try std.testing.expectEqual(Request.delete, @as(std.meta.Tag(Request), del));
    try std.testing.expectEqualStrings("TOPIC", del.delete.key);

    try std.testing.expectError(error.NeedMoreParams, parseLine("PROP #chan GET"));
    try std.testing.expectError(error.TooManyParams, parseLine("PROP #chan CLEAR TOPIC"));
}

test "secret channel props stay hidden except raw internal lookup" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const entity = try Entity.fromId("#keys");
    _ = try store.setProp(entity, "HOSTKEY", "s3cret", .{ .id = "owner", .access = .owner });

    try std.testing.expectError(error.PropMissing, store.getProp(entity, "HOSTKEY"));
    const raw = try store.getPropRaw(entity, "HOSTKEY");
    try std.testing.expectEqualStrings("HOSTKEY", raw.key);
    try std.testing.expectEqualStrings("s3cret", raw.value);

    // FOUNDERKEY is a secret tier key too — hidden from getProp, visible RAW.
    _ = try store.setProp(entity, "FOUNDERKEY", "topkey", .{ .id = "owner", .access = .owner });
    try std.testing.expect((channelPropInfo("FOUNDERKEY").?).secret);
    try std.testing.expect(channelPropKey("no-ai") == .no_ai);
    try std.testing.expect(channelPropKey("LOCAL-ONLY") == .local_only);
    try std.testing.expect(channelPropKey("server-ai-ok") == .server_ai_ok);
    try std.testing.expect(channelPropKey("history-policy") == .history_policy);
    try std.testing.expectError(error.PropMissing, store.getProp(entity, "FOUNDERKEY"));
    try std.testing.expectEqualStrings("topkey", (try store.getPropRaw(entity, "FOUNDERKEY")).value);

    // A plain LIST omits every secret key; listPropsRaw surfaces them for the
    // caller to gate (here: a non-secret CUSTOM plus the two secret tier keys).
    _ = try store.setProp(entity, "CUSTOM", "v", .{ .id = "owner", .access = .host });
    var views: [8]EntryView = undefined;
    const plain = try store.listProps(entity, &views);
    try std.testing.expectEqual(@as(usize, 1), plain.len);
    try std.testing.expectEqualStrings("CUSTOM", plain[0].key);
    var raw_views: [8]EntryView = undefined;
    const all = try store.listPropsRaw(entity, &raw_views);
    try std.testing.expectEqual(@as(usize, 3), all.len); // CUSTOM + HOSTKEY + FOUNDERKEY
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

    // MEMBERCOUNT is a computed read-only builtin; MEMBERLIMIT is host-settable.
    // (Checked via metadata + a default-limit store; the Tiny store's 8-byte key
    // cap would reject these long key names before the read-only rule applies.)
    try std.testing.expect(channelPropKey("MEMBERCOUNT").? == .membercount);
    try std.testing.expect(channelPropInfo("MEMBERCOUNT").?.read_only);
    try std.testing.expect(!channelPropInfo("MEMBERLIMIT").?.read_only);

    var full = DefaultStore.init(std.testing.allocator);
    defer full.deinit();
    const chan = try Entity.fromId("#mc");
    try std.testing.expectError(error.ReadOnlyProperty, full.setProp(chan, "MEMBERCOUNT", "1", .{ .id = "server", .access = .server }));
    _ = try full.setProp(chan, "MEMBERLIMIT", "50", .{ .id = "host", .access = .host });
}

test "user profile properties use the profile value limit" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const entity = try Entity.fromId("Alice");
    const setter = Setter{ .id = "Alice", .access = .member };
    const cases = [_]struct {
        key: []const u8,
        value: []const u8,
    }{
        .{ .key = "URL", .value = "https://example.test/alice" },
        .{ .key = "GENDER", .value = "nonbinary" },
        .{ .key = "PICTURE", .value = "https://example.test/a.png" },
        .{ .key = "BIO", .value = "Orochi operator" },
        .{ .key = "EMAIL", .value = "alice@example.test" },
    };

    for (cases) |case| {
        const ev = try store.setProp(entity, case.key, case.value, setter);
        try std.testing.expectEqualStrings(case.key, ev.key);
        try std.testing.expectEqualStrings(case.value, ev.value);
        try std.testing.expect(userProfilePropKey(case.key) != null);
    }

    var too_long = @as([(user_profile_max_value + 1)]u8, @splat('x'));
    try std.testing.expectError(error.InvalidValue, store.setProp(entity, "URL", too_long[0..], setter));

    // The tighter cap applies only to the newly added user-profile fields.
    // Existing Orochi profile keys and generic user props retain the store-wide
    // value budget.
    _ = try store.setProp(entity, "display", too_long[0..], setter);
    _ = try store.setProp(entity, "custom", too_long[0..], setter);
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

test "prepared public channel clone is exact deterministic and independently owned" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const source = try Entity.fromId("#Template");
    const destination = try Entity.fromId("#Clone");
    const member_a = try Entity.fromId("#Clone:Alice");
    const member_b = try Entity.fromId("#clone:Bob");
    const near_prefix_member = try Entity.fromId("#Clone2:Eve");
    const unrelated = try Entity.fromId("Watcher");
    try std.testing.expectEqual(EntityKind.member, member_a.kind);
    try std.testing.expectEqual(EntityKind.member, member_b.kind);

    _ = try store.setProp(source, "TOPIC", "source topic", .{ .id = "source-host", .access = .host });
    _ = try store.setProp(source, "CUSTOM", "source custom", .{ .id = "source-host", .access = .host });
    _ = try store.setProp(source, "HOSTKEY", "source-secret", .{ .id = "source-owner", .access = .owner });
    _ = try store.setProp(destination, "CUSTOM", "stale", .{ .id = "old-host", .access = .host });
    _ = try store.setProp(destination, "HOSTKEY", "destination-secret", .{ .id = "old-owner", .access = .owner });
    _ = try store.setProp(member_a, "ROLE", "old-op", .{ .id = "Alice", .access = .member });
    _ = try store.setProp(member_b, "NOTE", "old-note", .{ .id = "Bob", .access = .member });
    _ = try store.setProp(near_prefix_member, "ROLE", "keep-op", .{ .id = "Eve", .access = .member });
    _ = try store.setProp(unrelated, "BIO", "untouched", .{ .id = "Watcher", .access = .user });
    try std.testing.expectEqual(@as(usize, 6), store.entity_count);

    var ticket = try store.preparePublicChannelClone(source.id, destination.id);
    const replacements = ticket.replacementFacts();
    try std.testing.expectEqual(@as(usize, 2), replacements.len);
    try std.testing.expectEqualStrings("CUSTOM", replacements[0].key);
    try std.testing.expectEqualStrings("TOPIC", replacements[1].key);
    try std.testing.expectEqualStrings("source custom", replacements[0].value);
    try std.testing.expectEqualStrings("source-host", replacements[0].owner);
    try std.testing.expectEqual(AccessLevel.host, replacements[0].access);
    try std.testing.expectEqualStrings("source topic", replacements[1].value);
    try std.testing.expectEqualStrings("source-host", replacements[1].owner);
    try std.testing.expectEqual(AccessLevel.host, replacements[1].access);
    for (replacements) |fact| try std.testing.expectEqualStrings(destination.id, fact.entity.id);

    const purged = ticket.purgedFacts();
    try std.testing.expectEqual(@as(usize, 4), purged.len);
    try std.testing.expectEqual(EntityKind.channel, purged[0].entity.kind);
    try std.testing.expectEqualStrings("CUSTOM", purged[0].key);
    try std.testing.expectEqualStrings("HOSTKEY", purged[1].key);
    try std.testing.expectEqualStrings(member_a.id, purged[2].entity.id);
    try std.testing.expectEqualStrings("ROLE", purged[2].key);
    try std.testing.expectEqualStrings(member_b.id, purged[3].entity.id);
    try std.testing.expectEqualStrings("NOTE", purged[3].key);
    try std.testing.expectEqual(@as(usize, 3), ticket.purge_entity_keys.len);

    const staged = if (ticket.staged_state) |*state| state else return error.TestUnexpectedResult;
    try std.testing.expect(@intFromPtr(ticket.staged_outer_key.?.ptr) != @intFromPtr(staged.entity.id.ptr));
    try std.testing.expect(@intFromPtr(replacements[0].entity.id.ptr) != @intFromPtr(staged.entity.id.ptr));
    try std.testing.expect(@intFromPtr(replacements[0].entity.id.ptr) != @intFromPtr(replacements[1].entity.id.ptr));
    var staged_it = staged.props.iterator();
    while (staged_it.next()) |entry| {
        var preview: ?*const DefaultStore.PreparedPropFact = null;
        for (replacements) |*fact| {
            if (std.mem.eql(u8, fact.key, entry.value_ptr.key)) {
                preview = fact;
                break;
            }
        }
        const fact = preview orelse return error.TestUnexpectedResult;
        try std.testing.expect(@intFromPtr(entry.key_ptr.*.ptr) != @intFromPtr(entry.value_ptr.key.ptr));
        try std.testing.expect(@intFromPtr(fact.key.ptr) != @intFromPtr(entry.key_ptr.*.ptr));
        try std.testing.expect(@intFromPtr(fact.key.ptr) != @intFromPtr(entry.value_ptr.key.ptr));
        try std.testing.expect(@intFromPtr(fact.value.ptr) != @intFromPtr(entry.value_ptr.value.ptr));
        try std.testing.expect(@intFromPtr(fact.owner.ptr) != @intFromPtr(entry.value_ptr.owner.ptr));
    }
    const live_source_custom = try store.getPropRaw(source, "CUSTOM");
    try std.testing.expect(@intFromPtr(live_source_custom.value.ptr) != @intFromPtr(replacements[0].value.ptr));
    const live_destination_secret = try store.getPropRaw(destination, "HOSTKEY");
    try std.testing.expect(@intFromPtr(live_destination_secret.value.ptr) != @intFromPtr(purged[1].value.ptr));

    // Abort is exact and every lifecycle operation is idempotent.
    ticket.abort();
    ticket.abort();
    ticket.deinit();
    try std.testing.expectEqual(@as(usize, 6), store.entity_count);
    try std.testing.expectEqualStrings("stale", (try store.getPropRaw(destination, "CUSTOM")).value);
    try std.testing.expectEqualStrings("destination-secret", (try store.getPropRaw(destination, "HOSTKEY")).value);
    try std.testing.expectEqualStrings("old-op", (try store.getPropRaw(member_a, "ROLE")).value);

    var committed = try store.preparePublicChannelClone(source.id, destination.id);
    committed.commit();
    committed.commit();
    committed.abort();
    committed.deinit();
    try std.testing.expectEqual(@as(usize, 4), store.entity_count);
    try std.testing.expectEqualStrings("source custom", (try store.getPropRaw(destination, "CUSTOM")).value);
    try std.testing.expectEqualStrings("source topic", (try store.getPropRaw(destination, "TOPIC")).value);
    try std.testing.expectError(error.PropMissing, store.getPropRaw(destination, "HOSTKEY"));
    try std.testing.expectError(error.PropMissing, store.getPropRaw(member_a, "ROLE"));
    try std.testing.expectError(error.PropMissing, store.getPropRaw(member_b, "NOTE"));
    try std.testing.expectEqualStrings("keep-op", (try store.getPropRaw(near_prefix_member, "ROLE")).value);
    try std.testing.expectEqualStrings("source-secret", (try store.getPropRaw(source, "HOSTKEY")).value);
    try std.testing.expectEqualStrings("untouched", (try store.getPropRaw(unrelated, "BIO")).value);

    // The committed replacement owns bytes independently of the source.
    _ = try store.setProp(source, "CUSTOM", "source changed", .{ .id = "new-source", .access = .host });
    try std.testing.expectEqualStrings("source custom", (try store.getPropRaw(destination, "CUSTOM")).value);
    _ = try store.setProp(destination, "TOPIC", "destination changed", .{ .id = "new-dst", .access = .host });
    try std.testing.expectEqualStrings("source topic", (try store.getPropRaw(source, "TOPIC")).value);
}

test "prepared public channel clone rejects same fold and parser members round trip" {
    const member_request = try parseLine("PROP #room:Nick SET ROLE :operator");
    try std.testing.expectEqual(Request.set, @as(std.meta.Tag(Request), member_request));
    try std.testing.expectEqual(EntityKind.member, member_request.set.entity.kind);
    try std.testing.expectEqualStrings("#room:Nick", member_request.set.entity.id);

    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const source = try Entity.fromId("#Same");
    _ = try store.setProp(source, "CUSTOM", "preserved", .{ .id = "host", .access = .host });
    try std.testing.expectError(error.InvalidEntity, store.preparePublicChannelClone("#Same", "#sAME"));
    try std.testing.expectEqual(@as(usize, 1), store.entity_count);
    try std.testing.expectEqualStrings("preserved", (try store.getPropRaw(source, "CUSTOM")).value);
    try std.testing.expectError(
        error.InvalidEntity,
        store.setProp(.{ .kind = .channel, .id = "#room:Nick" }, "CUSTOM", "bad", .{ .id = "host", .access = .host }),
    );
}

test "prepared public channel clone secret-only source clears destination exactly" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const source = try Entity.fromId("#SecretTemplate");
    const destination = try Entity.fromId("#ClearMe");
    const member_a = try Entity.fromId("#ClearMe:Alice");
    const member_b = try Entity.fromId("#clearme:Bob");
    const unrelated = try Entity.fromId("Other");
    _ = try store.setProp(source, "HOSTKEY", "never-copy", .{ .id = "owner", .access = .owner });
    _ = try store.setProp(destination, "CUSTOM", "stale", .{ .id = "host", .access = .host });
    _ = try store.setProp(member_a, "ROLE", "op", .{ .id = "Alice", .access = .member });
    _ = try store.setProp(member_b, "ROLE", "voice", .{ .id = "Bob", .access = .member });
    _ = try store.setProp(unrelated, "CUSTOM", "keep", .{ .id = "Other", .access = .user });
    try std.testing.expectEqual(@as(usize, 5), store.entity_count);

    var ticket = try store.preparePublicChannelClone(source.id, destination.id);
    try std.testing.expectEqual(@as(usize, 0), ticket.replacementFacts().len);
    try std.testing.expectEqual(@as(usize, 3), ticket.purgedFacts().len);
    try std.testing.expect(ticket.staged_outer_key == null);
    try std.testing.expect(ticket.staged_state == null);
    ticket.commit();
    defer ticket.deinit();

    try std.testing.expectEqual(@as(usize, 2), store.entity_count);
    try std.testing.expectError(error.PropMissing, store.getPropRaw(destination, "CUSTOM"));
    try std.testing.expectError(error.PropMissing, store.getPropRaw(member_a, "ROLE"));
    try std.testing.expectError(error.PropMissing, store.getPropRaw(member_b, "ROLE"));
    try std.testing.expectEqualStrings("never-copy", (try store.getPropRaw(source, "HOSTKEY")).value);
    try std.testing.expectEqualStrings("keep", (try store.getPropRaw(unrelated, "CUSTOM")).value);
}

test "prepared public channel clone uses post-purge entity cap math" {
    const Capped = PropStore(.{ .max_entities = 5 });
    var store = Capped.init(std.testing.allocator);
    defer store.deinit();
    const source = try Entity.fromId("#Src");
    const destination = try Entity.fromId("#Dst");
    const member_a = try Entity.fromId("#Dst:A");
    const member_b = try Entity.fromId("#dst:B");
    const unrelated = try Entity.fromId("Other");
    _ = try store.setProp(source, "CUSTOM", "copy", .{ .id = "host", .access = .host });
    _ = try store.setProp(destination, "CUSTOM", "stale", .{ .id = "host", .access = .host });
    _ = try store.setProp(member_a, "ROLE", "a", .{ .id = "A", .access = .member });
    _ = try store.setProp(member_b, "ROLE", "b", .{ .id = "B", .access = .member });
    _ = try store.setProp(unrelated, "CUSTOM", "keep", .{ .id = "Other", .access = .user });
    try std.testing.expectEqual(@as(usize, 5), store.entity_count);
    var ticket = try store.preparePublicChannelClone(source.id, destination.id);
    ticket.commit();
    defer ticket.deinit();
    try std.testing.expectEqual(@as(usize, 3), store.entity_count);
    try std.testing.expectEqualStrings("copy", (try store.getPropRaw(destination, "CUSTOM")).value);
    try std.testing.expectError(error.PropMissing, store.getPropRaw(member_a, "ROLE"));
    try std.testing.expectError(error.PropMissing, store.getPropRaw(member_b, "ROLE"));

    const NoRoom = PropStore(.{ .max_entities = 2 });
    var no_room = NoRoom.init(std.testing.allocator);
    defer no_room.deinit();
    _ = try no_room.setProp(source, "CUSTOM", "copy", .{ .id = "host", .access = .host });
    _ = try no_room.setProp(unrelated, "CUSTOM", "keep", .{ .id = "Other", .access = .user });
    try std.testing.expectError(error.LimitReached, no_room.preparePublicChannelClone(source.id, "#Absent"));
    try std.testing.expectEqual(@as(usize, 2), no_room.entity_count);
    try std.testing.expectEqualStrings("copy", (try no_room.getPropRaw(source, "CUSTOM")).value);
    try std.testing.expectEqualStrings("keep", (try no_room.getPropRaw(unrelated, "CUSTOM")).value);
}

test "prepared public channel clone is atomic on every allocation boundary" {
    var fail_offset: usize = 0;
    while (true) : (fail_offset += 1) {
        try std.testing.expect(fail_offset < 256);
        const completed = blk: {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
            var store = DefaultStore.init(failing.allocator());
            defer {
                failing.fail_index = std.math.maxInt(usize);
                store.deinit();
            }

            const source = try Entity.fromId("#AllocSource");
            const destination = try Entity.fromId("#AllocDestination");
            const member = try Entity.fromId("#allocdestination:Nick");
            const unrelated = try Entity.fromId("Other");
            _ = try store.setProp(source, "CUSTOM", "copy", .{ .id = "source-host", .access = .host });
            _ = try store.setProp(source, "TOPIC", "copy-topic", .{ .id = "source-host", .access = .host });
            _ = try store.setProp(source, "HOSTKEY", "source-secret", .{ .id = "source-owner", .access = .owner });
            _ = try store.setProp(destination, "CUSTOM", "stale", .{ .id = "old-host", .access = .host });
            _ = try store.setProp(destination, "HOSTKEY", "destination-secret", .{ .id = "old-owner", .access = .owner });
            _ = try store.setProp(member, "ROLE", "old-role", .{ .id = "Nick", .access = .member });
            _ = try store.setProp(unrelated, "CUSTOM", "untouched", .{ .id = "Other", .access = .user });
            try std.testing.expectEqual(@as(usize, 4), store.entity_count);

            failing.fail_index = failing.alloc_index + fail_offset;
            var prepared = store.preparePublicChannelClone(source.id, destination.id) catch |err| {
                failing.fail_index = std.math.maxInt(usize);
                try std.testing.expectEqual(error.LimitReached, err);
                try std.testing.expect(failing.has_induced_failure);
                try std.testing.expectEqual(@as(usize, 4), store.entity_count);
                try std.testing.expectEqualStrings("copy", (try store.getPropRaw(source, "CUSTOM")).value);
                try std.testing.expectEqualStrings("copy-topic", (try store.getPropRaw(source, "TOPIC")).value);
                try std.testing.expectEqualStrings("source-secret", (try store.getPropRaw(source, "HOSTKEY")).value);
                try std.testing.expectEqualStrings("stale", (try store.getPropRaw(destination, "CUSTOM")).value);
                try std.testing.expectEqualStrings("destination-secret", (try store.getPropRaw(destination, "HOSTKEY")).value);
                try std.testing.expectEqualStrings("old-role", (try store.getPropRaw(member, "ROLE")).value);
                try std.testing.expectEqualStrings("untouched", (try store.getPropRaw(unrelated, "CUSTOM")).value);
                break :blk false;
            };
            try std.testing.expect(!failing.has_induced_failure);

            // Once preparation succeeds, abort remains allocation-free even
            // when the allocator would reject the very next allocation.
            failing.fail_index = failing.alloc_index;
            failing.has_induced_failure = false;
            prepared.abort();
            prepared.abort();
            prepared.deinit();
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqual(@as(usize, 4), store.entity_count);
            try std.testing.expectEqualStrings("stale", (try store.getPropRaw(destination, "CUSTOM")).value);
            try std.testing.expectEqualStrings("old-role", (try store.getPropRaw(member, "ROLE")).value);

            // Re-prepare without injection, then prove commit is also fully
            // allocation-free under an immediate-failure allocator.
            failing.fail_index = std.math.maxInt(usize);
            var committed = try store.preparePublicChannelClone(source.id, destination.id);
            failing.has_induced_failure = false;
            failing.fail_index = failing.alloc_index;
            committed.commit();
            committed.commit();
            committed.deinit();
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqual(@as(usize, 3), store.entity_count);
            try std.testing.expectEqualStrings("copy", (try store.getPropRaw(destination, "CUSTOM")).value);
            try std.testing.expectEqualStrings("copy-topic", (try store.getPropRaw(destination, "TOPIC")).value);
            try std.testing.expectError(error.PropMissing, store.getPropRaw(destination, "HOSTKEY"));
            try std.testing.expectError(error.PropMissing, store.getPropRaw(member, "ROLE"));
            try std.testing.expectEqualStrings("source-secret", (try store.getPropRaw(source, "HOSTKEY")).value);
            try std.testing.expectEqualStrings("untouched", (try store.getPropRaw(unrelated, "CUSTOM")).value);
            break :blk true;
        };
        if (completed) break;
    }
}

test "prepared public channel clone reserves a fresh target and handles an all-zero plan" {
    // Missing source plus missing destination is a valid no-op ticket, including
    // zero-length owned plans and repeated lifecycle calls.
    var empty_store = DefaultStore.init(std.testing.allocator);
    defer empty_store.deinit();
    var empty = try empty_store.preparePublicChannelClone("#Missing", "#FreshEmpty");
    try std.testing.expectEqual(@as(usize, 0), empty.replacementFacts().len);
    try std.testing.expectEqual(@as(usize, 0), empty.purgedFacts().len);
    empty.commit();
    empty.commit();
    empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty_store.entity_count);

    // Fill the live outer map to its load threshold so the absent-destination
    // branch must reserve a new map before returning a prepared ticket.
    var fail_offset: usize = 0;
    while (true) : (fail_offset += 1) {
        try std.testing.expect(fail_offset < 128);
        const completed = blk: {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
            var store = DefaultStore.init(failing.allocator());
            defer {
                failing.fail_index = std.math.maxInt(usize);
                store.deinit();
            }
            const source = try Entity.fromId("#FreshSource");
            const destination = try Entity.fromId("#FreshTarget");
            _ = try store.setProp(source, "CUSTOM", "fresh-copy", .{ .id = "host", .access = .host });

            const load_limit = (store.entities.capacity() * std.hash_map.default_max_load_percentage) / 100;
            var filler_index: usize = 0;
            var filler_buf: [32]u8 = undefined;
            while (store.entities.count() < load_limit) : (filler_index += 1) {
                const filler_id = std.fmt.bufPrint(&filler_buf, "Filler-{d}", .{filler_index}) catch unreachable;
                _ = try store.setProp(try Entity.fromId(filler_id), "CUSTOM", "keep", .{ .id = "filler", .access = .user });
            }
            try std.testing.expectEqual(load_limit, store.entities.count());
            const initial_count = store.entity_count;

            failing.fail_index = failing.alloc_index + fail_offset;
            var prepared = store.preparePublicChannelClone(source.id, destination.id) catch |err| {
                failing.fail_index = std.math.maxInt(usize);
                try std.testing.expectEqual(error.LimitReached, err);
                try std.testing.expect(failing.has_induced_failure);
                try std.testing.expectEqual(initial_count, store.entity_count);
                try std.testing.expectEqualStrings("fresh-copy", (try store.getPropRaw(source, "CUSTOM")).value);
                try std.testing.expectError(error.PropMissing, store.getPropRaw(destination, "CUSTOM"));
                break :blk false;
            };
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqual(@as(usize, 1), prepared.replacementFacts().len);
            try std.testing.expectEqual(@as(usize, 0), prepared.purgedFacts().len);

            failing.has_induced_failure = false;
            failing.fail_index = failing.alloc_index;
            prepared.commit();
            prepared.deinit();
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqual(initial_count + 1, store.entity_count);
            try std.testing.expectEqualStrings("fresh-copy", (try store.getPropRaw(source, "CUSTOM")).value);
            try std.testing.expectEqualStrings("fresh-copy", (try store.getPropRaw(destination, "CUSTOM")).value);
            break :blk true;
        };
        if (completed) break;
    }
}
