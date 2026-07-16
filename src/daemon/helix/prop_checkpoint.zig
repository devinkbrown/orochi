// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Atomic Helix checkpoint image for the raw IRCX PROP store and both PROP
//! convergence-clock maps. The outer codec owns its wire identity; the nested
//! PRPS payload remains an opaque, length-delimited PropStore checkpoint.

const std = @import("std");
const channel_prop_event = @import("../../proto/channel_prop_event.zig");
const entity_prop_event = @import("../../proto/entity_prop_event.zig");
const ircx_prop_store = @import("../../proto/ircx_prop_store.zig");

pub const DefaultStore = ircx_prop_store.DefaultStore;

pub const Error = std.mem.Allocator.Error || error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TrailingBytes,
    ChecksumMismatch,
    CheckpointTooLarge,
    CapacityExceeded,
    LengthMismatch,
    InvalidField,
    InvalidMapKey,
    DuplicateClock,
    NonCanonicalOrder,
    InvalidPropStore,
    HlcExhausted,
};

pub const ChannelClock = struct {
    channel: []u8,
    key: []u8,
    owner: []u8,
    hlc: u64,
    present: bool,
    origin_node: u64,
    origin_pubkey: []u8,
    origin_sig: []u8,

    pub fn deinit(self: *ChannelClock, allocator: std.mem.Allocator) void {
        allocator.free(self.channel);
        allocator.free(self.key);
        allocator.free(self.owner);
        allocator.free(self.origin_pubkey);
        allocator.free(self.origin_sig);
        self.* = undefined;
    }
};

pub const EntityClock = struct {
    kind: entity_prop_event.EntityKind,
    entity: []u8,
    key: []u8,
    owner: []u8,
    hlc: u64,
    present: bool,
    origin_node: u64,
    origin_pubkey: []u8,
    origin_sig: []u8,

    pub fn deinit(self: *EntityClock, allocator: std.mem.Allocator) void {
        allocator.free(self.entity);
        allocator.free(self.key);
        allocator.free(self.owner);
        allocator.free(self.origin_pubkey);
        allocator.free(self.origin_sig);
        self.* = undefined;
    }
};

pub const ChannelClockMap = std.StringHashMapUnmanaged(ChannelClock);
pub const EntityClockMap = std.StringHashMapUnmanaged(EntityClock);

/// Fully-owned successor image. It is movable and can be swapped into the
/// daemon without allocating or copying any clock row a second time.
pub const Restored = struct {
    allocator: std.mem.Allocator,
    props: DefaultStore,
    channel_clocks: ChannelClockMap = .empty,
    entity_clocks: EntityClockMap = .empty,
    /// Derived exclusively from decoded rows; never trusted from the wire.
    max_hlc: u64 = 0,

    /// Publish the complete decoded image without allocating or branching.
    /// The displaced triplet becomes owned by `self` and is destroyed by the
    /// caller's existing `defer restored.deinit()`.
    pub fn swapInto(
        self: *Restored,
        props: *DefaultStore,
        channel: *ChannelClockMap,
        entity: *EntityClockMap,
    ) void {
        std.mem.swap(DefaultStore, &self.props, props);
        std.mem.swap(ChannelClockMap, &self.channel_clocks, channel);
        std.mem.swap(EntityClockMap, &self.entity_clocks, entity);
    }

    pub fn deinit(self: *Restored) void {
        var channel_values = self.channel_clocks.valueIterator();
        while (channel_values.next()) |clock| clock.deinit(self.allocator);
        var channel_keys = self.channel_clocks.keyIterator();
        while (channel_keys.next()) |key| self.allocator.free(@constCast(key.*));
        self.channel_clocks.deinit(self.allocator);

        var entity_values = self.entity_clocks.valueIterator();
        while (entity_values.next()) |clock| clock.deinit(self.allocator);
        var entity_keys = self.entity_clocks.keyIterator();
        while (entity_keys.next()) |key| self.allocator.free(@constCast(key.*));
        self.entity_clocks.deinit(self.allocator);
        self.props.deinit();
        self.* = undefined;
    }
};

/// Fast outer-discriminator check. Full decode is still required before trust.
pub fn isUpgradeCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], &magic);
}

pub fn encode(
    allocator: std.mem.Allocator,
    props: *const DefaultStore,
    channel_clocks: *const ChannelClockMap,
    entity_clocks: *const EntityClockMap,
) Error![]u8 {
    if (channel_clocks.count() > std.math.maxInt(u32) or entity_clocks.count() > std.math.maxInt(u32))
        return error.CapacityExceeded;
    _ = try maxClockHlc(channel_clocks, entity_clocks);

    const prop_bytes = props.encodeCheckpoint(allocator) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidPropStore,
    };
    defer allocator.free(prop_bytes);
    if (prop_bytes.len > std.math.maxInt(u32)) return error.CheckpointTooLarge;

    const ordered_channels = try allocator.alloc(OrderedChannel, channel_clocks.count());
    defer allocator.free(ordered_channels);
    var channel_section_len: usize = 0;
    var channel_index: usize = 0;
    var channel_it = channel_clocks.iterator();
    while (channel_it.next()) |entry| : (channel_index += 1) {
        try validateChannelClock(entry.value_ptr);
        var expected_key_buf: [channel_prop_event.max_channel_len + 1 + channel_prop_event.max_key_len]u8 = undefined;
        const expected_key = writeChannelClockKey(
            &expected_key_buf,
            entry.value_ptr.channel,
            entry.value_ptr.key,
        ) orelse return error.InvalidField;
        if (!std.mem.eql(u8, entry.key_ptr.*, expected_key)) return error.InvalidMapKey;
        channel_section_len = try rowEncodedLen(channel_section_len, channel_row_prefix_len, &.{
            entry.value_ptr.channel,
            entry.value_ptr.key,
            entry.value_ptr.owner,
            entry.value_ptr.origin_pubkey,
            entry.value_ptr.origin_sig,
        });
        ordered_channels[channel_index] = .{ .map_key = entry.key_ptr.*, .clock = entry.value_ptr };
    }
    std.mem.sort(OrderedChannel, ordered_channels, {}, OrderedChannel.less);
    try rejectDuplicateChannelKeys(ordered_channels);

    const ordered_entities = try allocator.alloc(OrderedEntity, entity_clocks.count());
    defer allocator.free(ordered_entities);
    var entity_section_len: usize = 0;
    var entity_index: usize = 0;
    var entity_it = entity_clocks.iterator();
    while (entity_it.next()) |entry| : (entity_index += 1) {
        try validateEntityClock(entry.value_ptr);
        var expected_key_buf: [1 + entity_prop_event.max_entity_len + 1 + entity_prop_event.max_key_len]u8 = undefined;
        const expected_key = writeEntityClockKey(
            &expected_key_buf,
            entry.value_ptr.kind,
            entry.value_ptr.entity,
            entry.value_ptr.key,
        ) orelse return error.InvalidField;
        if (!std.mem.eql(u8, entry.key_ptr.*, expected_key)) return error.InvalidMapKey;
        entity_section_len = try rowEncodedLen(entity_section_len, entity_row_prefix_len, &.{
            entry.value_ptr.entity,
            entry.value_ptr.key,
            entry.value_ptr.owner,
            entry.value_ptr.origin_pubkey,
            entry.value_ptr.origin_sig,
        });
        ordered_entities[entity_index] = .{ .map_key = entry.key_ptr.*, .clock = entry.value_ptr };
    }
    std.mem.sort(OrderedEntity, ordered_entities, {}, OrderedEntity.less);
    try rejectDuplicateEntityKeys(ordered_entities);

    if (channel_section_len > std.math.maxInt(u32) or entity_section_len > std.math.maxInt(u32))
        return error.CheckpointTooLarge;
    var body_len = try addLen(prop_bytes.len, channel_section_len);
    body_len = try addLen(body_len, entity_section_len);
    if (body_len > std.math.maxInt(u32)) return error.CheckpointTooLarge;
    const prefix_len = try addLen(header_len, body_len);
    const total_len = try addLen(prefix_len, checksum_len);
    if (total_len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);

    @memcpy(out[0..magic.len], &magic);
    out[magic.len] = version;
    writeU32(out[5..9], @intCast(prop_bytes.len));
    writeU32(out[9..13], @intCast(ordered_channels.len));
    writeU32(out[13..17], @intCast(channel_section_len));
    writeU32(out[17..21], @intCast(ordered_entities.len));
    writeU32(out[21..25], @intCast(entity_section_len));
    writeU32(out[25..29], @intCast(body_len));

    var pos: usize = header_len;
    @memcpy(out[pos..][0..prop_bytes.len], prop_bytes);
    pos += prop_bytes.len;
    for (ordered_channels) |ordered| writeChannelRow(out, &pos, ordered.clock);
    for (ordered_entities) |ordered| writeEntityRow(out, &pos, ordered.clock);
    std.debug.assert(pos == prefix_len);
    checkpointChecksum(out[0..prefix_len], out[prefix_len..][0..checksum_len]);
    return out;
}

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!Restored {
    if (bytes.len < header_len + checksum_len) return error.Truncated;
    if (!isUpgradeCheckpoint(bytes)) return error.BadMagic;
    if (bytes[magic.len] != version) return error.UnsupportedVersion;

    const prop_len: usize = readU32(bytes[5..9]);
    const channel_count: usize = readU32(bytes[9..13]);
    const channel_len: usize = readU32(bytes[13..17]);
    const entity_count: usize = readU32(bytes[17..21]);
    const entity_len: usize = readU32(bytes[21..25]);
    const body_len: usize = readU32(bytes[25..29]);
    var declared_body_len = try addLen(prop_len, channel_len);
    declared_body_len = try addLen(declared_body_len, entity_len);
    if (declared_body_len != body_len) return error.LengthMismatch;
    const prefix_len = try addLen(header_len, body_len);
    const expected_len = try addLen(prefix_len, checksum_len);
    if (expected_len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;
    var actual_checksum: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0..prefix_len], &actual_checksum);
    const expected_checksum: [checksum_len]u8 = bytes[prefix_len..][0..checksum_len].*;
    if (!std.crypto.timing_safe.eql([checksum_len]u8, actual_checksum, expected_checksum))
        return error.ChecksumMismatch;

    const minimum_channel_len = std.math.mul(usize, channel_count, channel_row_prefix_len) catch
        return error.CheckpointTooLarge;
    const minimum_entity_len = std.math.mul(usize, entity_count, entity_row_prefix_len) catch
        return error.CheckpointTooLarge;
    if (minimum_channel_len > channel_len or minimum_entity_len > entity_len)
        return error.Truncated;

    const prop_start = header_len;
    const prop_end = prop_start + prop_len;
    const channel_end = prop_end + channel_len;
    const entity_end = channel_end + entity_len;
    std.debug.assert(entity_end == prefix_len);
    var restored = Restored{
        .allocator = allocator,
        .props = DefaultStore.decodeCheckpoint(allocator, bytes[prop_start..prop_end]) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidPropStore,
        },
    };
    errdefer restored.deinit();
    try restored.channel_clocks.ensureTotalCapacity(allocator, @intCast(channel_count));
    try restored.entity_clocks.ensureTotalCapacity(allocator, @intCast(entity_count));

    var pos = prop_end;
    var previous_channel_key: ?[]const u8 = null;
    for (0..channel_count) |_| {
        if (channel_end - pos < channel_row_prefix_len) return error.Truncated;
        const present_raw = bytes[pos];
        pos += 1;
        const hlc = readU64(bytes[pos..][0..8]);
        pos += 8;
        const origin_node = readU64(bytes[pos..][0..8]);
        pos += 8;
        const lengths = readFiveLengths(bytes, &pos);
        if (present_raw > 1) return error.InvalidField;
        const fields = try readClockFields(bytes, &pos, channel_end, lengths);
        const borrowed = ChannelClock{
            .channel = @constCast(fields.identity),
            .key = @constCast(fields.key),
            .owner = @constCast(fields.owner),
            .hlc = hlc,
            .present = present_raw == 1,
            .origin_node = origin_node,
            .origin_pubkey = @constCast(fields.origin_pubkey),
            .origin_sig = @constCast(fields.origin_sig),
        };
        try validateChannelClock(&borrowed);
        var derived_key_buf: [channel_prop_event.max_channel_len + 1 + channel_prop_event.max_key_len]u8 = undefined;
        const derived_key = writeChannelClockKey(&derived_key_buf, borrowed.channel, borrowed.key) orelse
            return error.InvalidField;
        try validateWireOrder(previous_channel_key, derived_key);
        var owned = try cloneChannelClock(allocator, derived_key, &borrowed);
        restored.channel_clocks.putAssumeCapacityNoClobber(owned.map_key, owned.clock);
        previous_channel_key = owned.map_key;
        restored.max_hlc = @max(restored.max_hlc, hlc);
        owned = undefined;
    }
    if (pos != channel_end) return if (pos < channel_end) error.TrailingBytes else error.Truncated;

    var previous_entity_key: ?[]const u8 = null;
    for (0..entity_count) |_| {
        if (entity_end - pos < entity_row_prefix_len) return error.Truncated;
        const kind_raw = bytes[pos];
        pos += 1;
        const kind = entity_prop_event.EntityKind.fromTag(kind_raw) orelse return error.InvalidField;
        const present_raw = bytes[pos];
        pos += 1;
        const hlc = readU64(bytes[pos..][0..8]);
        pos += 8;
        const origin_node = readU64(bytes[pos..][0..8]);
        pos += 8;
        const lengths = readFiveLengths(bytes, &pos);
        if (present_raw > 1) return error.InvalidField;
        const fields = try readClockFields(bytes, &pos, entity_end, lengths);
        const borrowed = EntityClock{
            .kind = kind,
            .entity = @constCast(fields.identity),
            .key = @constCast(fields.key),
            .owner = @constCast(fields.owner),
            .hlc = hlc,
            .present = present_raw == 1,
            .origin_node = origin_node,
            .origin_pubkey = @constCast(fields.origin_pubkey),
            .origin_sig = @constCast(fields.origin_sig),
        };
        try validateEntityClock(&borrowed);
        var derived_key_buf: [1 + entity_prop_event.max_entity_len + 1 + entity_prop_event.max_key_len]u8 = undefined;
        const derived_key = writeEntityClockKey(&derived_key_buf, kind, borrowed.entity, borrowed.key) orelse
            return error.InvalidField;
        try validateWireOrder(previous_entity_key, derived_key);
        var owned = try cloneEntityClock(allocator, derived_key, &borrowed);
        restored.entity_clocks.putAssumeCapacityNoClobber(owned.map_key, owned.clock);
        previous_entity_key = owned.map_key;
        restored.max_hlc = @max(restored.max_hlc, hlc);
        owned = undefined;
    }
    if (pos != entity_end) return if (pos < entity_end) error.TrailingBytes else error.Truncated;
    return restored;
}

pub fn maxClockHlc(
    channel_clocks: *const ChannelClockMap,
    entity_clocks: *const EntityClockMap,
) Error!u64 {
    var maximum: u64 = 0;
    var channel_values = channel_clocks.valueIterator();
    while (channel_values.next()) |clock| {
        if (clock.hlc == std.math.maxInt(u64)) return error.HlcExhausted;
        maximum = @max(maximum, clock.hlc);
    }
    var entity_values = entity_clocks.valueIterator();
    while (entity_values.next()) |clock| {
        if (clock.hlc == std.math.maxInt(u64)) return error.HlcExhausted;
        maximum = @max(maximum, clock.hlc);
    }
    return maximum;
}

pub fn writeChannelClockKey(out: []u8, channel: []const u8, key: []const u8) ?[]const u8 {
    const need = channel.len + 1 + key.len;
    if (out.len < need) return null;
    for (channel, 0..) |byte, index| out[index] = std.ascii.toLower(byte);
    out[channel.len] = 0x1f;
    for (key, 0..) |byte, index| out[channel.len + 1 + index] = std.ascii.toLower(byte);
    return out[0..need];
}

pub fn writeEntityClockKey(
    out: []u8,
    kind: entity_prop_event.EntityKind,
    entity: []const u8,
    key: []const u8,
) ?[]const u8 {
    const need = 1 + entity.len + 1 + key.len;
    if (out.len < need) return null;
    out[0] = @intFromEnum(kind);
    for (entity, 0..) |byte, index| out[1 + index] = std.ascii.toLower(byte);
    out[1 + entity.len] = 0x1f;
    for (key, 0..) |byte, index| out[1 + entity.len + 1 + index] = std.ascii.toLower(byte);
    return out[0..need];
}

const magic = [_]u8{ 'H', 'P', 'R', 'P' };
const version: u8 = 1;
const header_len: usize = 29;
const checksum_len: usize = std.crypto.hash.Blake3.digest_length;
const channel_row_prefix_len: usize = 1 + 8 + 8 + 5 * 4;
const entity_row_prefix_len: usize = 1 + 1 + 8 + 8 + 5 * 4;
const max_checkpoint_bytes: usize = 512 * 1024 * 1024;
const checksum_domain = "orochi-helix-prop-checkpoint-v1";

const OrderedChannel = struct {
    map_key: []const u8,
    clock: *const ChannelClock,

    fn less(_: void, lhs: OrderedChannel, rhs: OrderedChannel) bool {
        return std.mem.lessThan(u8, lhs.map_key, rhs.map_key);
    }
};

const OrderedEntity = struct {
    map_key: []const u8,
    clock: *const EntityClock,

    fn less(_: void, lhs: OrderedEntity, rhs: OrderedEntity) bool {
        return std.mem.lessThan(u8, lhs.map_key, rhs.map_key);
    }
};

const ClockLengths = struct {
    identity: usize,
    key: usize,
    owner: usize,
    origin_pubkey: usize,
    origin_sig: usize,
};

const ClockFields = struct {
    identity: []const u8,
    key: []const u8,
    owner: []const u8,
    origin_pubkey: []const u8,
    origin_sig: []const u8,
};

fn validateChannelClock(clock: *const ChannelClock) Error!void {
    if (clock.channel.len > channel_prop_event.max_channel_len or
        clock.key.len > channel_prop_event.max_key_len or
        clock.owner.len > channel_prop_event.max_owner_len) return error.InvalidField;
    try validateSignatureShape(clock.origin_pubkey, clock.origin_sig);
    if (clock.hlc == std.math.maxInt(u64)) return error.HlcExhausted;
}

fn validateEntityClock(clock: *const EntityClock) Error!void {
    if (clock.entity.len > entity_prop_event.max_entity_len or
        clock.key.len > entity_prop_event.max_key_len or
        clock.owner.len > entity_prop_event.max_owner_len) return error.InvalidField;
    try validateSignatureShape(clock.origin_pubkey, clock.origin_sig);
    if (clock.hlc == std.math.maxInt(u64)) return error.HlcExhausted;
}

fn validateSignatureShape(origin_pubkey: []const u8, origin_sig: []const u8) Error!void {
    if (origin_pubkey.len == 0 and origin_sig.len == 0) return;
    if (origin_pubkey.len != channel_prop_event.pubkey_len or origin_sig.len != channel_prop_event.sig_len)
        return error.InvalidField;
}

fn rowEncodedLen(total: usize, prefix: usize, fields: []const []const u8) Error!usize {
    var out = try addLen(total, prefix);
    for (fields) |field| out = try addLen(out, field.len);
    if (out > max_checkpoint_bytes) return error.CheckpointTooLarge;
    return out;
}

fn rejectDuplicateChannelKeys(rows: []const OrderedChannel) Error!void {
    if (rows.len < 2) return;
    for (rows[1..], rows[0..rows.len -| 1]) |current, previous| {
        if (std.mem.eql(u8, previous.map_key, current.map_key)) return error.DuplicateClock;
    }
}

fn rejectDuplicateEntityKeys(rows: []const OrderedEntity) Error!void {
    if (rows.len < 2) return;
    for (rows[1..], rows[0..rows.len -| 1]) |current, previous| {
        if (std.mem.eql(u8, previous.map_key, current.map_key)) return error.DuplicateClock;
    }
}

fn writeChannelRow(out: []u8, pos: *usize, clock: *const ChannelClock) void {
    out[pos.*] = @intFromBool(clock.present);
    pos.* += 1;
    writeU64(out[pos.*..][0..8], clock.hlc);
    pos.* += 8;
    writeU64(out[pos.*..][0..8], clock.origin_node);
    pos.* += 8;
    writeFiveLengths(out, pos, .{
        .identity = clock.channel.len,
        .key = clock.key.len,
        .owner = clock.owner.len,
        .origin_pubkey = clock.origin_pubkey.len,
        .origin_sig = clock.origin_sig.len,
    });
    writeClockFields(out, pos, clock.channel, clock.key, clock.owner, clock.origin_pubkey, clock.origin_sig);
}

fn writeEntityRow(out: []u8, pos: *usize, clock: *const EntityClock) void {
    out[pos.*] = @intFromEnum(clock.kind);
    pos.* += 1;
    out[pos.*] = @intFromBool(clock.present);
    pos.* += 1;
    writeU64(out[pos.*..][0..8], clock.hlc);
    pos.* += 8;
    writeU64(out[pos.*..][0..8], clock.origin_node);
    pos.* += 8;
    writeFiveLengths(out, pos, .{
        .identity = clock.entity.len,
        .key = clock.key.len,
        .owner = clock.owner.len,
        .origin_pubkey = clock.origin_pubkey.len,
        .origin_sig = clock.origin_sig.len,
    });
    writeClockFields(out, pos, clock.entity, clock.key, clock.owner, clock.origin_pubkey, clock.origin_sig);
}

fn writeFiveLengths(out: []u8, pos: *usize, lengths: ClockLengths) void {
    inline for (.{ lengths.identity, lengths.key, lengths.owner, lengths.origin_pubkey, lengths.origin_sig }) |len| {
        writeU32(out[pos.*..][0..4], @intCast(len));
        pos.* += 4;
    }
}

fn readFiveLengths(bytes: []const u8, pos: *usize) ClockLengths {
    const out = ClockLengths{
        .identity = readU32(bytes[pos.*..][0..4]),
        .key = readU32(bytes[pos.* + 4 ..][0..4]),
        .owner = readU32(bytes[pos.* + 8 ..][0..4]),
        .origin_pubkey = readU32(bytes[pos.* + 12 ..][0..4]),
        .origin_sig = readU32(bytes[pos.* + 16 ..][0..4]),
    };
    pos.* += 20;
    return out;
}

fn writeClockFields(
    out: []u8,
    pos: *usize,
    identity: []const u8,
    key: []const u8,
    owner: []const u8,
    origin_pubkey: []const u8,
    origin_sig: []const u8,
) void {
    inline for (.{ identity, key, owner, origin_pubkey, origin_sig }) |field| {
        @memcpy(out[pos.*..][0..field.len], field);
        pos.* += field.len;
    }
}

fn readClockFields(bytes: []const u8, pos: *usize, limit: usize, lengths: ClockLengths) Error!ClockFields {
    var total: usize = 0;
    inline for (.{ lengths.identity, lengths.key, lengths.owner, lengths.origin_pubkey, lengths.origin_sig }) |len|
        total = try addLen(total, len);
    if (pos.* > limit or total > limit - pos.*) return error.Truncated;
    return .{
        .identity = try take(bytes, pos, limit, lengths.identity),
        .key = try take(bytes, pos, limit, lengths.key),
        .owner = try take(bytes, pos, limit, lengths.owner),
        .origin_pubkey = try take(bytes, pos, limit, lengths.origin_pubkey),
        .origin_sig = try take(bytes, pos, limit, lengths.origin_sig),
    };
}

fn validateWireOrder(previous: ?[]const u8, current: []const u8) Error!void {
    if (previous) |prior| {
        if (std.mem.eql(u8, prior, current)) return error.DuplicateClock;
        if (!std.mem.lessThan(u8, prior, current)) return error.NonCanonicalOrder;
    }
}

fn cloneChannelClock(
    allocator: std.mem.Allocator,
    map_key_source: []const u8,
    source: *const ChannelClock,
) std.mem.Allocator.Error!struct { map_key: []u8, clock: ChannelClock } {
    const map_key = try allocator.dupe(u8, map_key_source);
    errdefer allocator.free(map_key);
    const channel = try allocator.dupe(u8, source.channel);
    errdefer allocator.free(channel);
    const key = try allocator.dupe(u8, source.key);
    errdefer allocator.free(key);
    const owner = try allocator.dupe(u8, source.owner);
    errdefer allocator.free(owner);
    const origin_pubkey = try allocator.dupe(u8, source.origin_pubkey);
    errdefer allocator.free(origin_pubkey);
    const origin_sig = try allocator.dupe(u8, source.origin_sig);
    return .{ .map_key = map_key, .clock = .{
        .channel = channel,
        .key = key,
        .owner = owner,
        .hlc = source.hlc,
        .present = source.present,
        .origin_node = source.origin_node,
        .origin_pubkey = origin_pubkey,
        .origin_sig = origin_sig,
    } };
}

fn cloneEntityClock(
    allocator: std.mem.Allocator,
    map_key_source: []const u8,
    source: *const EntityClock,
) std.mem.Allocator.Error!struct { map_key: []u8, clock: EntityClock } {
    const map_key = try allocator.dupe(u8, map_key_source);
    errdefer allocator.free(map_key);
    const entity = try allocator.dupe(u8, source.entity);
    errdefer allocator.free(entity);
    const key = try allocator.dupe(u8, source.key);
    errdefer allocator.free(key);
    const owner = try allocator.dupe(u8, source.owner);
    errdefer allocator.free(owner);
    const origin_pubkey = try allocator.dupe(u8, source.origin_pubkey);
    errdefer allocator.free(origin_pubkey);
    const origin_sig = try allocator.dupe(u8, source.origin_sig);
    return .{ .map_key = map_key, .clock = .{
        .kind = source.kind,
        .entity = entity,
        .key = key,
        .owner = owner,
        .hlc = source.hlc,
        .present = source.present,
        .origin_node = source.origin_node,
        .origin_pubkey = origin_pubkey,
        .origin_sig = origin_sig,
    } };
}

fn addLen(lhs: usize, rhs: usize) Error!usize {
    const sum = std.math.add(usize, lhs, rhs) catch return error.CheckpointTooLarge;
    if (sum > max_checkpoint_bytes) return error.CheckpointTooLarge;
    return sum;
}

fn take(bytes: []const u8, pos: *usize, limit: usize, len: usize) Error![]const u8 {
    if (pos.* > limit or len > limit - pos.*) return error.Truncated;
    const out = bytes[pos.* .. pos.* + len];
    pos.* += len;
    return out;
}

fn readU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .big);
}

fn writeU32(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .big);
}

fn readU64(bytes: *const [8]u8) u64 {
    return std.mem.readInt(u64, bytes, .big);
}

fn writeU64(bytes: *[8]u8, value: u64) void {
    std.mem.writeInt(u64, bytes, value, .big);
}

fn checkpointChecksum(prefix: []const u8, out: *[checksum_len]u8) void {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(checksum_domain);
    hasher.update(prefix);
    hasher.final(out);
}

fn testPutChannelClock(
    allocator: std.mem.Allocator,
    map: *ChannelClockMap,
    channel: []const u8,
    key: []const u8,
    owner: []const u8,
    hlc: u64,
    present: bool,
    origin_node: u64,
    origin_pubkey: []const u8,
    origin_sig: []const u8,
) !void {
    var key_buf: [channel_prop_event.max_channel_len + 1 + channel_prop_event.max_key_len]u8 = undefined;
    const map_key = writeChannelClockKey(&key_buf, channel, key) orelse return error.TestUnexpectedResult;
    try map.ensureUnusedCapacity(allocator, 1);
    const borrowed = ChannelClock{
        .channel = @constCast(channel),
        .key = @constCast(key),
        .owner = @constCast(owner),
        .hlc = hlc,
        .present = present,
        .origin_node = origin_node,
        .origin_pubkey = @constCast(origin_pubkey),
        .origin_sig = @constCast(origin_sig),
    };
    var owned = try cloneChannelClock(allocator, map_key, &borrowed);
    map.putAssumeCapacityNoClobber(owned.map_key, owned.clock);
    owned = undefined;
}

fn testPutEntityClock(
    allocator: std.mem.Allocator,
    map: *EntityClockMap,
    kind: entity_prop_event.EntityKind,
    entity: []const u8,
    key: []const u8,
    owner: []const u8,
    hlc: u64,
    present: bool,
    origin_node: u64,
    origin_pubkey: []const u8,
    origin_sig: []const u8,
) !void {
    var key_buf: [1 + entity_prop_event.max_entity_len + 1 + entity_prop_event.max_key_len]u8 = undefined;
    const map_key = writeEntityClockKey(&key_buf, kind, entity, key) orelse return error.TestUnexpectedResult;
    try map.ensureUnusedCapacity(allocator, 1);
    const borrowed = EntityClock{
        .kind = kind,
        .entity = @constCast(entity),
        .key = @constCast(key),
        .owner = @constCast(owner),
        .hlc = hlc,
        .present = present,
        .origin_node = origin_node,
        .origin_pubkey = @constCast(origin_pubkey),
        .origin_sig = @constCast(origin_sig),
    };
    var owned = try cloneEntityClock(allocator, map_key, &borrowed);
    map.putAssumeCapacityNoClobber(owned.map_key, owned.clock);
    owned = undefined;
}

fn testDeinitChannelMap(allocator: std.mem.Allocator, map: *ChannelClockMap) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(@constCast(entry.key_ptr.*));
        entry.value_ptr.deinit(allocator);
    }
    map.deinit(allocator);
    map.* = .empty;
}

fn testDeinitEntityMap(allocator: std.mem.Allocator, map: *EntityClockMap) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(@constCast(entry.key_ptr.*));
        entry.value_ptr.deinit(allocator);
    }
    map.deinit(allocator);
    map.* = .empty;
}

fn testInstallFixture(
    allocator: std.mem.Allocator,
    props: *DefaultStore,
    channels: *ChannelClockMap,
    entities: *EntityClockMap,
    reverse: bool,
) !void {
    const channel = try ircx_prop_store.Entity.fromId("#Room");
    const user = try ircx_prop_store.Entity.fromId("CaseUser");
    const member = try ircx_prop_store.Entity.fromId("#Room:Nick");
    if (reverse) {
        _ = try props.setProp(member, "ROLE", "operator", .{ .id = "Nick", .access = .member });
        _ = try props.setProp(user, "BIO", "profile", .{ .id = "CaseUser", .access = .user });
        _ = try props.setProp(channel, "HOSTKEY", "secret", .{ .id = "founder", .access = .owner });
        _ = try props.setProp(channel, "TOPIC", "hello", .{ .id = "host", .access = .host });
    } else {
        _ = try props.setProp(channel, "TOPIC", "hello", .{ .id = "host", .access = .host });
        _ = try props.setProp(channel, "HOSTKEY", "secret", .{ .id = "founder", .access = .owner });
        _ = try props.setProp(user, "BIO", "profile", .{ .id = "CaseUser", .access = .user });
        _ = try props.setProp(member, "ROLE", "operator", .{ .id = "Nick", .access = .member });
    }

    const pubkey: [channel_prop_event.pubkey_len]u8 = @splat(0x41);
    const sig: [channel_prop_event.sig_len]u8 = @splat(0x52);
    if (reverse) {
        try testPutChannelClock(allocator, channels, "#Bravo", "KEYBB", "bob", 20, false, 2, "", "");
        try testPutChannelClock(allocator, channels, "#Alpha", "KEYAA", "alice", 10, true, 1, &pubkey, &sig);
        // Bounded malformed tombstone state is live-reachable today and must
        // survive exact migration even though a new PROP write would reject it.
        try testPutChannelClock(allocator, channels, "", "", "bad owner:\n", 5, false, 9, "", "");
        try testPutEntityClock(allocator, entities, .user, "Bobby", "STAT2", "bob", 60, true, 4, &pubkey, &sig);
        try testPutEntityClock(allocator, entities, .user, "Alice", "STAT1", "alice", 30, true, 3, "", "");
        try testPutEntityClock(allocator, entities, .member, "", "", "", 40, false, 8, "", "");
    } else {
        try testPutChannelClock(allocator, channels, "", "", "bad owner:\n", 5, false, 9, "", "");
        try testPutChannelClock(allocator, channels, "#Alpha", "KEYAA", "alice", 10, true, 1, &pubkey, &sig);
        try testPutChannelClock(allocator, channels, "#Bravo", "KEYBB", "bob", 20, false, 2, "", "");
        try testPutEntityClock(allocator, entities, .member, "", "", "", 40, false, 8, "", "");
        try testPutEntityClock(allocator, entities, .user, "Alice", "STAT1", "alice", 30, true, 3, "", "");
        try testPutEntityClock(allocator, entities, .user, "Bobby", "STAT2", "bob", 60, true, 4, &pubkey, &sig);
    }
}

fn testSliceAliases(bytes: []const u8, slice: []const u8) bool {
    const bytes_start = @intFromPtr(bytes.ptr);
    const bytes_end = bytes_start + bytes.len;
    const slice_start = @intFromPtr(slice.ptr);
    const slice_end = slice_start + slice.len;
    return slice_start < bytes_end and bytes_start < slice_end;
}

fn testRewriteChecksum(bytes: []u8) void {
    const prefix_len = header_len + @as(usize, readU32(bytes[25..29]));
    checkpointChecksum(bytes[0..prefix_len], bytes[prefix_len..][0..checksum_len]);
}

fn testFindChannelRow(bytes: []const u8, channel: []const u8, key: []const u8) ?usize {
    var pos = header_len + @as(usize, readU32(bytes[5..9]));
    const limit = pos + @as(usize, readU32(bytes[13..17]));
    for (0..@as(usize, readU32(bytes[9..13]))) |_| {
        if (limit - pos < channel_row_prefix_len) return null;
        const start = pos;
        var lengths_pos = start + 17;
        const lengths = readFiveLengths(bytes, &lengths_pos);
        var fields_pos = start + channel_row_prefix_len;
        const fields = readClockFields(bytes, &fields_pos, limit, lengths) catch return null;
        if (std.mem.eql(u8, fields.identity, channel) and std.mem.eql(u8, fields.key, key)) return start;
        pos = fields_pos;
    }
    return null;
}

fn testFindEntityRow(
    bytes: []const u8,
    kind: entity_prop_event.EntityKind,
    entity: []const u8,
    key: []const u8,
) ?usize {
    const prop_end = header_len + @as(usize, readU32(bytes[5..9]));
    var pos = prop_end + @as(usize, readU32(bytes[13..17]));
    const limit = pos + @as(usize, readU32(bytes[21..25]));
    for (0..@as(usize, readU32(bytes[17..21]))) |_| {
        if (limit - pos < entity_row_prefix_len) return null;
        const start = pos;
        var lengths_pos = start + 18;
        const lengths = readFiveLengths(bytes, &lengths_pos);
        var fields_pos = start + entity_row_prefix_len;
        const fields = readClockFields(bytes, &fields_pos, limit, lengths) catch return null;
        if (bytes[start] == @intFromEnum(kind) and
            std.mem.eql(u8, fields.identity, entity) and
            std.mem.eql(u8, fields.key, key)) return start;
        pos = fields_pos;
    }
    return null;
}

test "Helix PROP checkpoint is deterministic complete owned and swap-ready" {
    const testing = std.testing;
    var first_props = DefaultStore.init(testing.allocator);
    defer first_props.deinit();
    var first_channels: ChannelClockMap = .empty;
    defer testDeinitChannelMap(testing.allocator, &first_channels);
    var first_entities: EntityClockMap = .empty;
    defer testDeinitEntityMap(testing.allocator, &first_entities);
    try testInstallFixture(testing.allocator, &first_props, &first_channels, &first_entities, false);

    var second_props = DefaultStore.init(testing.allocator);
    defer second_props.deinit();
    var second_channels: ChannelClockMap = .empty;
    defer testDeinitChannelMap(testing.allocator, &second_channels);
    var second_entities: EntityClockMap = .empty;
    defer testDeinitEntityMap(testing.allocator, &second_entities);
    try testInstallFixture(testing.allocator, &second_props, &second_channels, &second_entities, true);

    const first_wire = try encode(testing.allocator, &first_props, &first_channels, &first_entities);
    defer testing.allocator.free(first_wire);
    const second_wire = try encode(testing.allocator, &second_props, &second_channels, &second_entities);
    defer testing.allocator.free(second_wire);
    try testing.expect(isUpgradeCheckpoint(first_wire));
    try testing.expectEqualSlices(u8, first_wire, second_wire);

    var restored = try decode(testing.allocator, first_wire);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 3), restored.channel_clocks.count());
    try testing.expectEqual(@as(usize, 3), restored.entity_clocks.count());
    try testing.expectEqual(@as(u64, 60), restored.max_hlc);
    try testing.expectEqualStrings(
        "secret",
        (try restored.props.getPropRaw(try ircx_prop_store.Entity.fromId("#Room"), "HOSTKEY")).value,
    );

    var malformed_channel_key_buf: [1]u8 = undefined;
    const malformed_channel_key = writeChannelClockKey(&malformed_channel_key_buf, "", "") orelse
        return error.TestUnexpectedResult;
    const malformed_channel = restored.channel_clocks.getPtr(malformed_channel_key) orelse
        return error.TestUnexpectedResult;
    try testing.expect(!malformed_channel.present);
    try testing.expectEqualStrings("bad owner:\n", malformed_channel.owner);
    try testing.expectEqual(@as(usize, 0), malformed_channel.origin_pubkey.len);
    try testing.expectEqual(@as(usize, 0), malformed_channel.origin_sig.len);

    var alpha_key_buf: [channel_prop_event.max_channel_len + 1 + channel_prop_event.max_key_len]u8 = undefined;
    const alpha_key = writeChannelClockKey(&alpha_key_buf, "#Alpha", "KEYAA") orelse
        return error.TestUnexpectedResult;
    const alpha_entry = restored.channel_clocks.getEntry(alpha_key) orelse return error.TestUnexpectedResult;
    try testing.expect(@intFromPtr(alpha_entry.key_ptr.*.ptr) != @intFromPtr(alpha_entry.value_ptr.channel.ptr));
    try testing.expect(@intFromPtr(alpha_entry.key_ptr.*.ptr) != @intFromPtr(alpha_entry.value_ptr.key.ptr));
    try testing.expect(!testSliceAliases(first_wire, alpha_entry.key_ptr.*));
    try testing.expect(!testSliceAliases(first_wire, alpha_entry.value_ptr.channel));
    try testing.expect(!testSliceAliases(first_wire, alpha_entry.value_ptr.key));
    try testing.expect(!testSliceAliases(first_wire, alpha_entry.value_ptr.owner));
    try testing.expect(!testSliceAliases(first_wire, alpha_entry.value_ptr.origin_pubkey));
    try testing.expect(!testSliceAliases(first_wire, alpha_entry.value_ptr.origin_sig));

    var bobby_key_buf: [1 + entity_prop_event.max_entity_len + 1 + entity_prop_event.max_key_len]u8 = undefined;
    const bobby_key = writeEntityClockKey(&bobby_key_buf, .user, "Bobby", "STAT2") orelse
        return error.TestUnexpectedResult;
    const bobby_entry = restored.entity_clocks.getEntry(bobby_key) orelse return error.TestUnexpectedResult;
    try testing.expect(@intFromPtr(bobby_entry.key_ptr.*.ptr) != @intFromPtr(bobby_entry.value_ptr.entity.ptr));
    try testing.expect(@intFromPtr(bobby_entry.key_ptr.*.ptr) != @intFromPtr(bobby_entry.value_ptr.key.ptr));
    try testing.expect(!testSliceAliases(first_wire, bobby_entry.key_ptr.*));
    try testing.expect(!testSliceAliases(first_wire, bobby_entry.value_ptr.entity));
    try testing.expect(!testSliceAliases(first_wire, bobby_entry.value_ptr.key));
    try testing.expect(!testSliceAliases(first_wire, bobby_entry.value_ptr.owner));
    try testing.expect(!testSliceAliases(first_wire, bobby_entry.value_ptr.origin_pubkey));
    try testing.expect(!testSliceAliases(first_wire, bobby_entry.value_ptr.origin_sig));

    const round_trip = try encode(
        testing.allocator,
        &restored.props,
        &restored.channel_clocks,
        &restored.entity_clocks,
    );
    defer testing.allocator.free(round_trip);
    try testing.expectEqualSlices(u8, first_wire, round_trip);

    var live_props = DefaultStore.init(testing.allocator);
    defer live_props.deinit();
    const sentinel = try ircx_prop_store.Entity.fromId("Sentinel");
    _ = try live_props.setProp(sentinel, "CUSTOM", "old", .{ .id = "Sentinel", .access = .user });
    var live_channels: ChannelClockMap = .empty;
    defer testDeinitChannelMap(testing.allocator, &live_channels);
    var live_entities: EntityClockMap = .empty;
    defer testDeinitEntityMap(testing.allocator, &live_entities);
    restored.swapInto(&live_props, &live_channels, &live_entities);
    try testing.expectError(error.PropMissing, live_props.getPropRaw(sentinel, "CUSTOM"));
    try testing.expectEqual(@as(usize, 3), live_channels.count());
    try testing.expectEqual(@as(usize, 3), live_entities.count());
    try testing.expectEqual(@as(usize, 1), restored.props.entity_count);
    try testing.expectEqual(@as(usize, 0), restored.channel_clocks.count());
    try testing.expectEqual(@as(usize, 0), restored.entity_clocks.count());
}

test "Helix PROP checkpoint rejects corrupt noncanonical and impossible wires before publication" {
    const testing = std.testing;
    var props = DefaultStore.init(testing.allocator);
    defer props.deinit();
    var channels: ChannelClockMap = .empty;
    defer testDeinitChannelMap(testing.allocator, &channels);
    var entities: EntityClockMap = .empty;
    defer testDeinitEntityMap(testing.allocator, &entities);
    try testInstallFixture(testing.allocator, &props, &channels, &entities, false);
    const checkpoint = try encode(testing.allocator, &props, &channels, &entities);
    defer testing.allocator.free(checkpoint);

    // Every strict prefix is rejected and therefore can never publish a
    // partially decoded predecessor image.
    for (0..checkpoint.len) |prefix_len| {
        if (decode(testing.allocator, checkpoint[0..prefix_len])) |decoded_value| {
            var decoded = decoded_value;
            decoded.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
    }

    const bad_magic = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(bad_magic);
    bad_magic[0] ^= 1;
    try testing.expectError(error.BadMagic, decode(testing.allocator, bad_magic));
    const bad_version = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(bad_version);
    bad_version[4] +%= 1;
    try testing.expectError(error.UnsupportedVersion, decode(testing.allocator, bad_version));
    const trailing = try testing.allocator.alloc(u8, checkpoint.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..checkpoint.len], checkpoint);
    trailing[checkpoint.len] = 0xa5;
    try testing.expectError(error.TrailingBytes, decode(testing.allocator, trailing));
    const bitflip = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(bitflip);
    bitflip[header_len + 1] ^= 1;
    try testing.expectError(error.ChecksumMismatch, decode(testing.allocator, bitflip));

    const mismatched_body = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(mismatched_body);
    writeU32(mismatched_body[25..29], readU32(mismatched_body[25..29]) + 1);
    try testing.expectError(error.LengthMismatch, decode(testing.allocator, mismatched_body));

    const alpha_start = testFindChannelRow(checkpoint, "#Alpha", "KEYAA") orelse
        return error.TestUnexpectedResult;
    const bravo_start = testFindChannelRow(checkpoint, "#Bravo", "KEYBB") orelse
        return error.TestUnexpectedResult;
    const alice_start = testFindEntityRow(checkpoint, .user, "Alice", "STAT1") orelse
        return error.TestUnexpectedResult;
    const bobby_start = testFindEntityRow(checkpoint, .user, "Bobby", "STAT2") orelse
        return error.TestUnexpectedResult;

    const invalid_bool = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(invalid_bool);
    invalid_bool[alpha_start] = 2;
    testRewriteChecksum(invalid_bool);
    try testing.expectError(error.InvalidField, decode(testing.allocator, invalid_bool));
    const invalid_kind = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(invalid_kind);
    invalid_kind[alice_start] = 0xff;
    testRewriteChecksum(invalid_kind);
    try testing.expectError(error.InvalidField, decode(testing.allocator, invalid_kind));

    const malformed_signature = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(malformed_signature);
    // channel row length slots: identity, key, owner, public key, signature.
    writeU32(malformed_signature[alpha_start + 29 ..][0..4], channel_prop_event.pubkey_len - 1);
    testRewriteChecksum(malformed_signature);
    try testing.expectError(error.InvalidField, decode(testing.allocator, malformed_signature));

    const exhausted_hlc = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(exhausted_hlc);
    writeU64(exhausted_hlc[alpha_start + 1 ..][0..8], std.math.maxInt(u64));
    testRewriteChecksum(exhausted_hlc);
    try testing.expectError(error.HlcExhausted, decode(testing.allocator, exhausted_hlc));

    const duplicate_channel = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(duplicate_channel);
    @memcpy(duplicate_channel[bravo_start + channel_row_prefix_len ..][0..6], "#aLpHa");
    @memcpy(duplicate_channel[bravo_start + channel_row_prefix_len + 6 ..][0..5], "keyaa");
    testRewriteChecksum(duplicate_channel);
    try testing.expectError(error.DuplicateClock, decode(testing.allocator, duplicate_channel));
    const reversed_channels = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(reversed_channels);
    @memcpy(reversed_channels[alpha_start + channel_row_prefix_len ..][0..6], "#Zulu!");
    testRewriteChecksum(reversed_channels);
    try testing.expectError(error.NonCanonicalOrder, decode(testing.allocator, reversed_channels));

    const duplicate_entity = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(duplicate_entity);
    @memcpy(duplicate_entity[bobby_start + entity_row_prefix_len ..][0..5], "aLiCe");
    @memcpy(duplicate_entity[bobby_start + entity_row_prefix_len + 5 ..][0..5], "stat1");
    testRewriteChecksum(duplicate_entity);
    try testing.expectError(error.DuplicateClock, decode(testing.allocator, duplicate_entity));
    const reversed_entities = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(reversed_entities);
    @memcpy(reversed_entities[alice_start + entity_row_prefix_len ..][0..5], "Zlice");
    testRewriteChecksum(reversed_entities);
    try testing.expectError(error.NonCanonicalOrder, decode(testing.allocator, reversed_entities));

    // Counts are authenticated and within u32, but cannot fit in the declared
    // section. This structural rejection must happen before any allocation.
    const allocation_bomb = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(allocation_bomb);
    writeU32(allocation_bomb[9..13], std.math.maxInt(u32));
    testRewriteChecksum(allocation_bomb);
    var fail_immediately = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.Truncated, decode(fail_immediately.allocator(), allocation_bomb));
    try testing.expect(!fail_immediately.has_induced_failure);

    var live_props = DefaultStore.init(testing.allocator);
    defer live_props.deinit();
    const sentinel = try ircx_prop_store.Entity.fromId("Sentinel");
    _ = try live_props.setProp(sentinel, "CUSTOM", "untouched", .{ .id = "Sentinel", .access = .user });
    var live_channels: ChannelClockMap = .empty;
    defer testDeinitChannelMap(testing.allocator, &live_channels);
    var live_entities: EntityClockMap = .empty;
    defer testDeinitEntityMap(testing.allocator, &live_entities);
    const corruptions = [_][]const u8{
        bitflip,
        invalid_bool,
        invalid_kind,
        malformed_signature,
        exhausted_hlc,
        duplicate_channel,
        reversed_channels,
        duplicate_entity,
        reversed_entities,
        allocation_bomb,
        trailing,
    };
    for (corruptions) |corrupt| {
        if (decode(testing.allocator, corrupt)) |decoded_value| {
            var decoded = decoded_value;
            decoded.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
        try testing.expectEqualStrings("untouched", (try live_props.getPropRaw(sentinel, "CUSTOM")).value);
        try testing.expectEqual(@as(usize, 0), live_channels.count());
        try testing.expectEqual(@as(usize, 0), live_entities.count());
    }
}

test "Helix PROP checkpoint has no property-store-derived clock row cap" {
    const testing = std.testing;
    var props = DefaultStore.init(testing.allocator);
    defer props.deinit();
    var channels: ChannelClockMap = .empty;
    defer testDeinitChannelMap(testing.allocator, &channels);
    var entities: EntityClockMap = .empty;
    defer testDeinitEntityMap(testing.allocator, &entities);

    // These clocks intentionally have no corresponding property rows. Their
    // cardinality is convergence state, not a PropStore entity/property cap.
    for (0..96) |index| {
        var identity_buf: [32]u8 = undefined;
        var key_buf: [32]u8 = undefined;
        const channel = try std.fmt.bufPrint(&identity_buf, "#Clock-{d}", .{index});
        const key = try std.fmt.bufPrint(&key_buf, "KEY-{d}", .{index});
        try testPutChannelClock(
            testing.allocator,
            &channels,
            channel,
            key,
            "legacy owner",
            @intCast(index + 1),
            index % 2 == 0,
            @intCast(index),
            "",
            "",
        );
        const entity = try std.fmt.bufPrint(&identity_buf, "ClockUser-{d}", .{index});
        try testPutEntityClock(
            testing.allocator,
            &entities,
            .user,
            entity,
            key,
            "",
            @intCast(1000 + index),
            false,
            @intCast(index),
            "",
            "",
        );
    }
    try testing.expectEqual(@as(usize, 0), props.entity_count);
    const checkpoint = try encode(testing.allocator, &props, &channels, &entities);
    defer testing.allocator.free(checkpoint);
    var restored = try decode(testing.allocator, checkpoint);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 96), restored.channel_clocks.count());
    try testing.expectEqual(@as(usize, 96), restored.entity_clocks.count());
    try testing.expectEqual(@as(u64, 1095), restored.max_hlc);
    try testing.expectEqual(@as(usize, 0), restored.props.entity_count);
}

test "Helix PROP checkpoint encode validates maps signatures and HLC exhaustion" {
    const testing = std.testing;
    var props = DefaultStore.init(testing.allocator);
    defer props.deinit();
    var channels: ChannelClockMap = .empty;
    defer testDeinitChannelMap(testing.allocator, &channels);
    var entities: EntityClockMap = .empty;
    defer testDeinitEntityMap(testing.allocator, &entities);
    try testInstallFixture(testing.allocator, &props, &channels, &entities, false);

    var alpha_key_buf: [channel_prop_event.max_channel_len + 1 + channel_prop_event.max_key_len]u8 = undefined;
    const alpha_key = writeChannelClockKey(&alpha_key_buf, "#Alpha", "KEYAA") orelse
        return error.TestUnexpectedResult;
    const alpha_entry = channels.getEntry(alpha_key) orelse return error.TestUnexpectedResult;

    const mutable_map_key = @constCast(alpha_entry.key_ptr.*);
    const saved_map_byte = mutable_map_key[0];
    mutable_map_key[0] ^= 1;
    try testing.expectError(error.InvalidMapKey, encode(testing.allocator, &props, &channels, &entities));
    mutable_map_key[0] = saved_map_byte;

    const saved_pubkey = alpha_entry.value_ptr.origin_pubkey;
    alpha_entry.value_ptr.origin_pubkey = saved_pubkey[0 .. saved_pubkey.len - 1];
    try testing.expectError(error.InvalidField, encode(testing.allocator, &props, &channels, &entities));
    alpha_entry.value_ptr.origin_pubkey = saved_pubkey;

    const saved_hlc = alpha_entry.value_ptr.hlc;
    alpha_entry.value_ptr.hlc = std.math.maxInt(u64);
    try testing.expectError(error.HlcExhausted, maxClockHlc(&channels, &entities));
    try testing.expectError(error.HlcExhausted, encode(testing.allocator, &props, &channels, &entities));
    alpha_entry.value_ptr.hlc = saved_hlc;

    const checkpoint = try encode(testing.allocator, &props, &channels, &entities);
    defer testing.allocator.free(checkpoint);
    var restored = try decode(testing.allocator, checkpoint);
    defer restored.deinit();
    try testing.expectEqual(@as(u64, 60), try maxClockHlc(&restored.channel_clocks, &restored.entity_clocks));
}

test "Helix PROP checkpoint encode and decode exhaust allocation failures" {
    const testing = std.testing;
    var props = DefaultStore.init(testing.allocator);
    defer props.deinit();
    var channels: ChannelClockMap = .empty;
    defer testDeinitChannelMap(testing.allocator, &channels);
    var entities: EntityClockMap = .empty;
    defer testDeinitEntityMap(testing.allocator, &entities);
    try testInstallFixture(testing.allocator, &props, &channels, &entities, false);

    const EncodeSweep = struct {
        fn run(
            allocator: std.mem.Allocator,
            store: *const DefaultStore,
            channel_map: *const ChannelClockMap,
            entity_map: *const EntityClockMap,
        ) !void {
            const bytes = try encode(allocator, store, channel_map, entity_map);
            defer allocator.free(bytes);
            try testing.expect(bytes.len > header_len + checksum_len);
        }
    };
    try testing.checkAllAllocationFailures(
        testing.allocator,
        EncodeSweep.run,
        .{ &props, &channels, &entities },
    );

    const checkpoint = try encode(testing.allocator, &props, &channels, &entities);
    defer testing.allocator.free(checkpoint);
    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var restored = try decode(allocator, bytes);
            defer restored.deinit();
            try testing.expectEqual(@as(usize, 3), restored.channel_clocks.count());
            try testing.expectEqual(@as(usize, 3), restored.entity_clocks.count());
            try testing.expectEqual(@as(u64, 60), restored.max_hlc);
            // Unsigned rows own allocator-compatible zero-length slices; the
            // deferred deinit is part of every allocation-failure iteration.
            var key_buf: [channel_prop_event.max_channel_len + 1 + channel_prop_event.max_key_len]u8 = undefined;
            const key = writeChannelClockKey(&key_buf, "#Bravo", "KEYBB") orelse
                return error.TestUnexpectedResult;
            const unsigned = restored.channel_clocks.getPtr(key) orelse return error.TestUnexpectedResult;
            try testing.expectEqual(@as(usize, 0), unsigned.origin_pubkey.len);
            try testing.expectEqual(@as(usize, 0), unsigned.origin_sig.len);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, DecodeSweep.run, .{checkpoint});
}
