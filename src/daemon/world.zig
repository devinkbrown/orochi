//! Single-server chat world state.
//!
//! This module intentionally models only local daemon state: nick ownership,
//! channel membership, and channel topics. It has no S2S/CRDT responsibilities.
const std = @import("std");
const rwlock = @import("../substrate/rwlock.zig");
const ebr = @import("../substrate/ebr.zig");
const world_rcu = @import("world_rcu.zig");

/// Lazily-created RCU mirror of the nick registry (the lock-free read path).
/// Heap-allocated so the EBR domain has a stable address: registered writer and
/// per-thread reader participants plus the registry's borrowed `&domain` must
/// stay valid after the owning `World` is moved (World.init returns by value).
/// Activated lazily and, once live, drives EVERY nick read (`findNick`) and collision check — the read
/// hot path is lock-free at the registry level and case-insensitive (RFC1459-ish
/// ASCII casemapping; "Alice" and "alice" are the same nick). `client_nicks`
/// remains the authoritative id->nick reverse index; the RCU registry is
/// authoritative for nick->id.
const RcuNickState = struct {
    domain: ebr.Domain,
    generation: usize,
    /// Writer-side participant used for CoW publish/retire. Readers must never
    /// share it; they use a per-thread participant from `rcuReaderParticipant`.
    writer_participant: *ebr.Participant,
    nicks: world_rcu.NickRegistry,
};

/// Marker value stored in the RCU channel-existence mirror. The mirror only
/// answers "does this channel name exist?" (lock-free, case-insensitive); the
/// authoritative `Channel` records live in `World.channels`. We store the
/// channel OID as a witness so the value type is a plain integer (no dangling
/// pointer into the rehash-prone `channels` map).
const RcuChannelState = struct {
    domain: ebr.Domain,
    generation: usize,
    /// Writer-side participant used for CoW publish/retire. Readers must never
    /// share it; they use a per-thread participant from `rcuReaderParticipant`.
    writer_participant: *ebr.Participant,
    /// channel name -> OID witness (existence set).
    names: world_rcu.ChannelRegistry(u32),
    /// One membership set per live channel, keyed by case-folded channel name.
    /// The MembershipSet values are heap-allocated for stable addresses (the
    /// AutoHashMap may rehash). All share the same EBR `domain`; writers use
    /// `writer_participant`, and readers use per-thread participants.
    members: std.StringHashMapUnmanaged(*world_rcu.MembershipSet) = .empty,
};

const rcu_tls_slot_count: usize = ebr.max_participants;

const RcuTlsEntry = struct {
    domain: ?*ebr.Domain = null,
    generation: usize = 0,
    participant: ?*ebr.Participant = null,
};

threadlocal var rcu_tls_entries: [rcu_tls_slot_count]RcuTlsEntry = [_]RcuTlsEntry{.{}} ** rcu_tls_slot_count;
var rcu_generation = std.atomic.Value(usize).init(1);

fn nextRcuGeneration() usize {
    return rcu_generation.fetchAdd(1, .monotonic);
}

fn rcuReaderParticipant(domain: *ebr.Domain, generation: usize) ebr.RegisterError!*ebr.Participant {
    var free_slot: ?usize = null;
    for (&rcu_tls_entries, 0..) |*entry, i| {
        if (entry.participant) |p| {
            if (entry.domain == domain and entry.generation == generation) return p;
        } else if (free_slot == null) {
            free_slot = i;
        }
    }

    const idx = free_slot orelse return error.TooManyParticipants;
    const p = try domain.register();
    rcu_tls_entries[idx] = .{
        .domain = domain,
        .generation = generation,
        .participant = p,
    };
    return p;
}

fn rcuForgetThreadParticipants(domain: *ebr.Domain, generation: usize) void {
    for (&rcu_tls_entries) |*entry| {
        if (entry.participant) |p| {
            if (entry.domain == domain and entry.generation == generation) {
                p.unregister();
                entry.* = .{};
            }
        }
    }
}

/// Opaque client handle value used by the local server world.
pub const ClientId = packed struct {
    shard: u12,
    slot: u20,
    gen: u32,

    pub const invalid: ClientId = .{
        .shard = std.math.maxInt(u12),
        .slot = std.math.maxInt(u20),
        .gen = std.math.maxInt(u32),
    };

    pub fn eql(self: ClientId, other: ClientId) bool {
        return self.shard == other.shard and
            self.slot == other.slot and
            self.gen == other.gen;
    }
};

pub const WorldError = std.mem.Allocator.Error || error{
    NickInUse,
    NoSuchChannel,
    NotOnChannel,
    NoSuchNick,
    UnsupportedMode,
    /// A channel list mode (+b/+e/+I/+Z) is at its `max_list_entries` cap.
    ListFull,
};

pub const MessageTarget = union(enum) {
    channel: []const u8,
    nick: ClientId,
};

/// ASCII case-insensitive hash-map context for `[]const u8` keys, matching the
/// RCU registries' `CaseInsensitiveBytesContext`. Used for the authoritative
/// `channels` map so that channel-name lookups (`getPtr`/`get`/`contains`) agree
/// with the case-insensitive RCU existence/membership mirrors — JOIN "#Room"
/// then PART "#room" must hit the same channel.
const CiStringContext = struct {
    pub fn hash(_: CiStringContext, key: []const u8) u64 {
        var h = std.hash.Wyhash.init(0);
        for (key) |c| {
            const lc = std.ascii.toLower(c);
            h.update(std.mem.asBytes(&lc));
        }
        return h.final();
    }
    pub fn eql(_: CiStringContext, a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;
        for (a, b) |ca, cb| {
            if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
        }
        return true;
    }
};

/// Case-insensitive `[]const u8`-keyed hash map (channel names).
fn CiStringHashMap(comptime V: type) type {
    return std.HashMap([]const u8, V, CiStringContext, std.hash_map.default_max_load_percentage);
}

const chanmode = @import("chanmode.zig");
const chanmode_ext = @import("../proto/chanmode_ext.zig");
const listx = @import("../proto/listx.zig");
const extban = @import("../proto/extban.zig");

/// Per-member channel status modes (op @, voice + — no halfop) keyed by client.
const MemberMap = std.AutoHashMap(ClientId, chanmode.MemberModes);
pub const MemberIterator = MemberMap.KeyIterator;
pub const MemberMode = chanmode.MemberMode;
pub const MemberModes = chanmode.MemberModes;
pub const ChannelMode = chanmode.ChannelMode;

const Channel = struct {
    allocator: std.mem.Allocator,
    members: MemberMap,
    topic: ?[]u8 = null,
    topic_setter: ?[]u8 = null,
    topic_time: i64 = 0,
    /// Channel-level flag modes (i/m/n/t/s).
    modes: chanmode.ChannelModes = chanmode.ChannelModes.empty(),
    /// +k key — allocator-owned heap (safe across HashMap rehash; never a
    /// self-slice). Null = no key.
    key: ?[]u8 = null,
    /// +l member limit. Null = unlimited.
    limit: ?u32 = null,
    /// +b ban masks (nick!user@host globs), allocator-owned with setter metadata.
    bans: std.ArrayListUnmanaged(ListEntry) = .empty,
    /// +e ban-exception masks: a match here overrides a +b ban on JOIN.
    exempts: std.ArrayListUnmanaged(ListEntry) = .empty,
    /// +I invite-exception masks: a match here lets a user bypass +i on JOIN.
    invex: std.ArrayListUnmanaged(ListEntry) = .empty,
    /// +Z quiet (MUTE) masks: a match suppresses *speech* (not join), like a
    /// ban that only mutes. Honors +e exempts.
    mutes: std.ArrayListUnmanaged(ListEntry) = .empty,
    /// +j join throttle: at most `throttle_joins` joins per `throttle_secs`
    /// window (0 = disabled). `throttle_times` is a bounded ring of recent
    /// successful join timestamps (ms) used to enforce the window.
    throttle_joins: u16 = 0,
    throttle_secs: u32 = 0,
    throttle_times: std.ArrayListUnmanaged(i64) = .empty,
    /// Pending invitations (INVITE) that satisfy +i, by client id.
    invites: std.AutoHashMapUnmanaged(ClientId, void) = .empty,
    /// +f forward target: when a join here is refused (+i/+k/+b/+l), the user is
    /// redirected to JOIN this channel instead. Allocator-owned; null = no forward.
    forward: ?[]u8 = null,
    /// +p private (shown but flagged) and +h IRCX HIDDEN (omitted from LIST).
    private: bool = false,
    hidden: bool = false,
    /// IRCX extended channel flags (AUTHONLY/AUDITORIUM/NOWHISPER/etc.) that have
    /// no slot in the base ChannelModes letter set.
    ext_modes: chanmode_ext.ExtChannelFlags = chanmode_ext.ExtChannelFlags.empty(),
    /// IRCX object id, assigned once at creation (0 = unset). Surfaced as the
    /// channel OID built-in property.
    oid: u32 = 0,
    /// Unix seconds when the channel was created (0 = unset). Surfaced as the
    /// IRCX CREATION built-in property. Sourced from World.clock_unix.
    created_unix: i64 = 0,

    fn init(allocator: std.mem.Allocator) Channel {
        return .{
            .allocator = allocator,
            .members = MemberMap.init(allocator),
            .modes = defaultChannelModes(),
        };
    }

    fn deinit(self: *Channel) void {
        if (self.topic) |topic| self.allocator.free(topic);
        if (self.topic_setter) |setter| self.allocator.free(setter);
        if (self.key) |k| self.allocator.free(k);
        if (self.forward) |f| self.allocator.free(f);
        for (self.bans.items) |*b| b.deinit(self.allocator);
        self.bans.deinit(self.allocator);
        for (self.exempts.items) |*e| e.deinit(self.allocator);
        self.exempts.deinit(self.allocator);
        for (self.invex.items) |*i| i.deinit(self.allocator);
        self.invex.deinit(self.allocator);
        for (self.mutes.items) |*m| m.deinit(self.allocator);
        self.mutes.deinit(self.allocator);
        self.throttle_times.deinit(self.allocator);
        self.invites.deinit(self.allocator);
        self.members.deinit();
        self.* = undefined;
    }

    fn setTopic(self: *Channel, topic: []const u8, setter: []const u8, set_at: i64) std.mem.Allocator.Error!void {
        const owned = try self.allocator.dupe(u8, topic);
        errdefer self.allocator.free(owned);
        const owned_setter = try self.allocator.dupe(u8, setter);
        if (self.topic) |old| self.allocator.free(old);
        if (self.topic_setter) |old| self.allocator.free(old);
        self.topic = owned;
        self.topic_setter = owned_setter;
        self.topic_time = set_at;
    }
};

fn defaultChannelModes() chanmode.ChannelModes {
    var modes = chanmode.ChannelModes.empty();
    modes.no_external = true;
    modes.topic_ops = true;
    return modes;
}

pub const ListEntry = struct {
    mask: []u8,
    setter: []u8,
    set_at: i64,

    fn init(allocator: std.mem.Allocator, mask: []const u8, setter: []const u8, set_at: i64) std.mem.Allocator.Error!ListEntry {
        const owned_mask = try allocator.dupe(u8, mask);
        errdefer allocator.free(owned_mask);
        const owned_setter = try allocator.dupe(u8, setter);
        return .{ .mask = owned_mask, .setter = owned_setter, .set_at = set_at };
    }

    fn deinit(self: *ListEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.mask);
        allocator.free(self.setter);
        self.* = undefined;
    }
};

pub const TopicInfo = struct {
    text: []const u8,
    setter: []const u8,
    set_at: i64,
};

/// Owned local nick/channel registry.
pub const World = struct {
    allocator: std.mem.Allocator,
    /// Per-channel cap on each list mode (+b/+e/+I/+Z); set from config at boot.
    max_list_entries: usize = 100,
    channels: CiStringHashMap(Channel),
    nicks: std.StringHashMap(ClientId),
    client_nicks: std.AutoHashMap(ClientId, []u8),
    /// Monotonic IRCX object-id source. Each newly-created channel gets the next
    /// value; starts at 1 so 0 means "unset" (never a real OID).
    next_oid: u32 = 1,
    /// Current wall-clock time in unix seconds, refreshed by the server before
    /// dispatch so `ensureChannel` can stamp a channel's CREATION time without the
    /// pure world taking a clock dependency. 0 until first set.
    clock_unix: i64 = 0,
    /// Lazily-activated RCU mirror of `nicks` (lock-free reads). Null until the
    /// first `findNickRcu`; once active, `registerNick`/`unregisterNick` keep it
    /// in sync. The authoritative map is still `nicks` — this is the parallel
    /// read path being validated ahead of the live flip (see
    /// docs/planning/24-multithreading.md, world.zig adoption map).
    rcu_nicks: ?*RcuNickState = null,
    rcu_nick_writes_since_advance: usize = 0,
    /// Lazily-activated RCU mirror of channel existence + per-channel membership
    /// (lock-free reads for `channelExists`/`isMember`). Null until the first
    /// channel is created; once active, `ensureChannel`/`removeChannel`/`join`/
    /// `part`/`removeClient` keep it in sync. Case-insensitive end-to-end.
    rcu_channels: ?*RcuChannelState = null,
    rcu_channel_writes_since_advance: usize = 0,
    /// Guards all of the maps above for the multi-reactor model: lookups take the
    /// read lock, mutations (join/part/nick/mode/rename/remove) the write lock.
    /// Every mutation — and its allocation — happens under the exclusive lock, so
    /// the allocator is never touched concurrently; reads are concurrent and
    /// allocation-free. Uncontended with a single reactor (the current default),
    /// so the live single-thread path pays only a couple of atomics. The World
    /// owns the lock so it travels with the data it guards; callers (the reactor
    /// loop) bracket world access with lockRead/lockWrite — see
    /// docs/planning/24-multithreading.md (Phase B).
    lock: rwlock.RwLock = .{},

    pub fn lockRead(self: *World) void {
        self.lock.lockShared();
    }
    pub fn unlockRead(self: *World) void {
        self.lock.unlockShared();
    }
    pub fn lockWrite(self: *World) void {
        self.lock.lockExclusive();
    }
    pub fn unlockWrite(self: *World) void {
        self.lock.unlockExclusive();
    }

    pub fn init(allocator: std.mem.Allocator) World {
        return .{
            .allocator = allocator,
            .channels = CiStringHashMap(Channel).init(allocator),
            .nicks = std.StringHashMap(ClientId).init(allocator),
            .client_nicks = std.AutoHashMap(ClientId, []u8).init(allocator),
        };
    }

    pub fn deinit(self: *World) void {
        var channel_it = self.channels.iterator();
        while (channel_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit();
        }
        self.channels.deinit();

        self.nicks.deinit();

        var nick_it = self.client_nicks.iterator();
        while (nick_it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.client_nicks.deinit();

        if (self.rcu_nicks) |r| {
            // Order: free the live snapshot, drain retired boxes/keys from the
            // domain limbo, unregister the reader slot, then tear down the
            // (now-quiescent) domain and free the heap state.
            r.nicks.deinit();
            r.domain.drainAll();
            r.writer_participant.unregister();
            rcuForgetThreadParticipants(&r.domain, r.generation);
            r.domain.deinit();
            self.allocator.destroy(r);
        }

        if (self.rcu_channels) |c| {
            // Free every per-channel membership set's live snapshot, then the
            // name-existence registry, before draining the shared domain. Same
            // proven order as the nick mirror: registries → drain → unregister
            // → domain deinit → destroy.
            var mit = c.members.iterator();
            while (mit.next()) |entry| {
                entry.value_ptr.*.deinit();
                self.allocator.free(entry.key_ptr.*);
                self.allocator.destroy(entry.value_ptr.*);
            }
            c.members.deinit(self.allocator);
            c.names.deinit();
            c.domain.drainAll();
            c.writer_participant.unregister();
            rcuForgetThreadParticipants(&c.domain, c.generation);
            c.domain.deinit();
            self.allocator.destroy(c);
        }
        self.* = undefined;
    }

    /// Activate (once) and return the lazy RCU nick mirror. Heap-allocated for a
    /// stable EBR-domain address; see `RcuNickState`.
    fn ensureRcuNicks(self: *World) !*RcuNickState {
        if (self.rcu_nicks) |r| return r;
        const r = try self.allocator.create(RcuNickState);
        errdefer self.allocator.destroy(r);
        r.domain = ebr.Domain.init(self.allocator);
        errdefer r.domain.deinit();
        r.generation = nextRcuGeneration();
        r.writer_participant = r.domain.register() catch return error.OutOfMemory;
        errdefer r.writer_participant.unregister();
        r.nicks = try world_rcu.NickRegistry.init(self.allocator, &r.domain);
        self.rcu_nicks = r;
        return r;
    }

    /// Activate (once) and return the lazy RCU channel/membership mirror.
    fn ensureRcuChannels(self: *World) !*RcuChannelState {
        if (self.rcu_channels) |c| return c;
        const c = try self.allocator.create(RcuChannelState);
        errdefer self.allocator.destroy(c);
        c.domain = ebr.Domain.init(self.allocator);
        errdefer c.domain.deinit();
        c.generation = nextRcuGeneration();
        c.writer_participant = c.domain.register() catch return error.OutOfMemory;
        errdefer c.writer_participant.unregister();
        c.names = try world_rcu.ChannelRegistry(u32).init(self.allocator, &c.domain);
        errdefer c.names.deinit();
        c.members = .empty;
        self.rcu_channels = c;
        return c;
    }

    fn noteRcuNickWrite(self: *World, r: *RcuNickState) void {
        if (self.rcu_nick_writes_since_advance < rcuAdvanceWriteInterval)
            self.rcu_nick_writes_since_advance += 1;
        if (self.rcu_nick_writes_since_advance < rcuAdvanceWriteInterval) return;
        if (advanceRcuDomainIfIdle(&r.domain))
            self.rcu_nick_writes_since_advance = 0;
    }

    fn noteRcuChannelWrite(self: *World, c: *RcuChannelState) void {
        if (self.rcu_channel_writes_since_advance < rcuAdvanceWriteInterval)
            self.rcu_channel_writes_since_advance += 1;
        if (self.rcu_channel_writes_since_advance < rcuAdvanceWriteInterval) return;
        if (advanceRcuDomainIfIdle(&c.domain))
            self.rcu_channel_writes_since_advance = 0;
    }

    /// Get (creating if absent) the per-channel RCU membership set for `name`.
    /// Keyed by the case-folded channel name so "#X" and "#x" share one set.
    fn rcuMembershipSet(self: *World, c: *RcuChannelState, name: []const u8) !*world_rcu.MembershipSet {
        var key_buf: [foldBufLen]u8 = undefined;
        const folded = foldName(name, &key_buf);
        if (c.members.get(folded)) |set| return set;

        const owned_key = try self.allocator.dupe(u8, folded);
        errdefer self.allocator.free(owned_key);
        const set = try self.allocator.create(world_rcu.MembershipSet);
        errdefer self.allocator.destroy(set);
        set.* = try world_rcu.MembershipSet.init(self.allocator, &c.domain);
        errdefer set.deinit();
        try c.members.put(self.allocator, owned_key, set);
        return set;
    }

    /// Return the existing per-channel RCU membership set for `name`, or null if
    /// none has been created. Does not allocate.
    fn rcuMembershipGet(c: *RcuChannelState, name: []const u8) ?*world_rcu.MembershipSet {
        var key_buf: [foldBufLen]u8 = undefined;
        const folded = foldName(name, &key_buf);
        return c.members.get(folded);
    }

    /// Re-key the per-channel membership set from `old` to `new` (channel
    /// rename). Membership is unchanged, so we move the set pointer to the new
    /// folded key. If the folded keys coincide, nothing to do.
    fn rcuRenameMembership(self: *World, c: *RcuChannelState, old: []const u8, new: []const u8) void {
        var ob: [foldBufLen]u8 = undefined;
        var nb: [foldBufLen]u8 = undefined;
        const of = foldName(old, &ob);
        const nf = foldName(new, &nb);
        if (std.mem.eql(u8, of, nf)) return;

        const kv = c.members.fetchRemove(of) orelse return;
        // Free the moved-out old key; install the set under a freshly-duped new
        // key. On dupe/put failure the set is dropped (best-effort) rather than
        // leaked under the wrong key.
        self.allocator.free(kv.key);
        const new_owned = self.allocator.dupe(u8, nf) catch {
            kv.value.deinit();
            self.allocator.destroy(kv.value);
            return;
        };
        // If a set already lives under the new key (case-fold collision), drop it
        // first so we don't leak.
        if (c.members.fetchRemove(nf)) |existing| {
            existing.value.deinit();
            self.allocator.free(existing.key);
            self.allocator.destroy(existing.value);
        }
        c.members.put(self.allocator, new_owned, kv.value) catch {
            self.allocator.free(new_owned);
            kv.value.deinit();
            self.allocator.destroy(kv.value);
        };
    }

    /// Drop the per-channel RCU membership set for `name` (channel removed).
    fn rcuDropMembership(self: *World, c: *RcuChannelState, name: []const u8) void {
        var key_buf: [foldBufLen]u8 = undefined;
        const folded = foldName(name, &key_buf);
        if (c.members.fetchRemove(folded)) |kv| {
            kv.value.deinit();
            self.allocator.free(kv.key);
            self.allocator.destroy(kv.value);
        }
    }

    /// Register `nick` for `client`, rejecting collisions. Collision detection
    /// is CASE-INSENSITIVE (RFC1459-ish ASCII casemapping): registering "Alice"
    /// then "alice" is a collision, not two entries. The RCU registry is the
    /// authoritative nick->id source (lock-free reads); `client_nicks` is the
    /// authoritative id->nick reverse index and `nicks` is kept as a consistent
    /// case-sensitive fallback mirror.
    pub fn registerNick(self: *World, nick: []const u8, client: ClientId) WorldError!void {
        // Activate the RCU mirror up front so reads are always served from it.
        const r = try self.ensureRcuNicks();

        // Case-insensitive collision check against the authoritative RCU map.
        if (r.nicks.lookup(r.writer_participant, nick)) |existing| {
            if ((@as(ClientId, @bitCast(existing))).eql(client)) {
                // Same owner: a pure case change ("Alice" -> "ALICE") still
                // updates the stored display form below; otherwise no-op.
                if (self.nickOf(client)) |cur| {
                    if (std.mem.eql(u8, cur, nick)) return;
                }
            } else {
                return error.NickInUse;
            }
        }

        if (self.client_nicks.contains(client)) {
            self.unregisterNick(client);
        }

        const owned = try self.allocator.dupe(u8, nick);
        errdefer self.allocator.free(owned);

        // Authoritative nick->id lives in the RCU registry (case-insensitive).
        try r.nicks.set(r.writer_participant, nick, @bitCast(client));
        self.noteRcuNickWrite(r);
        errdefer {
            r.nicks.remove(r.writer_participant, nick) catch {};
            self.noteRcuNickWrite(r);
        }

        try self.nicks.put(owned, client);
        errdefer _ = self.nicks.remove(owned);

        try self.client_nicks.put(client, owned);
    }

    /// Remove any nick owned by `client`.
    pub fn unregisterNick(self: *World, client: ClientId) void {
        if (self.client_nicks.fetchRemove(client)) |removed| {
            // Remove from the authoritative RCU map using the nick string before
            // it is freed below.
            if (self.rcu_nicks) |r| {
                r.nicks.remove(r.writer_participant, removed.value) catch {};
                self.noteRcuNickWrite(r);
            }
            _ = self.nicks.remove(removed.value);
            self.allocator.free(removed.value);
        }
    }

    pub fn nickOf(self: *const World, client: ClientId) ?[]const u8 {
        return self.client_nicks.get(client);
    }

    fn findNickFallback(self: *const World, nick: []const u8) ?ClientId {
        if (self.nicks.get(nick)) |id| return id;
        var it = self.nicks.iterator();
        while (it.next()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, nick)) return entry.value_ptr.*;
        }
        return null;
    }

    /// Look up the owner of `nick` (CASE-INSENSITIVE). Reads from the lock-free
    /// RCU registry when active (the common case after any nick registers);
    /// falls back to the case-sensitive `nicks` map only when the mirror has
    /// never been activated. `rcu_nicks` is a pointer, so we can pin and look up
    /// through it even from `*const World`.
    pub fn findNick(self: *const World, nick: []const u8) ?ClientId {
        if (self.rcu_nicks) |r| {
            const p = rcuReaderParticipant(&r.domain, r.generation) catch return self.findNickFallback(nick);
            if (r.nicks.lookup(p, nick)) |id| return @as(ClientId, @bitCast(id));
            return null;
        }
        return self.findNickFallback(nick);
    }

    /// Lock-free nick lookup via the RCU mirror (activates it on first use).
    /// Retained for callers that want to force the RCU path; `findNick` now uses
    /// the same registry once active.
    pub fn findNickRcu(self: *World, nick: []const u8) !?ClientId {
        const r = try self.ensureRcuNicks();
        const p = try rcuReaderParticipant(&r.domain, r.generation);
        if (r.nicks.lookup(p, nick)) |id| return @as(ClientId, @bitCast(id));
        return null;
    }

    /// Join a channel. Returns true when membership was newly added.
    pub fn join(self: *World, name: []const u8, client: ClientId) WorldError!bool {
        const channel = try self.ensureChannel(name);
        // The first member to join a freshly-created channel is its FOUNDER
        // (Orochi founder tier +Q, prefix ! — above IRCX owner); later
        // joiners start with no status modes.
        const founding = channel.members.count() == 0 and !channel.ext_modes.has(.registered);
        const member = try channel.members.getOrPut(client);
        if (!member.found_existing) {
            member.value_ptr.* = if (founding)
                MemberModes.fromModes(&.{.founder})
            else
                MemberModes.empty();
            // Mirror the new membership into the lock-free set.
            if (self.rcu_channels) |c| {
                const set = try self.rcuMembershipSet(c, name);
                try set.add(c.writer_participant, @bitCast(client));
                self.noteRcuChannelWrite(c);
            }
        }
        return !member.found_existing;
    }

    /// Re-attach `client` to `name` with EXACT `modes` (Helix UPGRADE carry-over).
    /// Ensures the channel exists and sets the member's status modes verbatim,
    /// bypassing the founder-on-first-join rule so restored state is faithful.
    pub fn restoreMember(self: *World, name: []const u8, client: ClientId, modes: MemberModes) WorldError!void {
        const channel = try self.ensureChannel(name);
        const member = try channel.members.getOrPut(client);
        const was_new = !member.found_existing;
        member.value_ptr.* = modes;
        if (was_new) {
            if (self.rcu_channels) |c| {
                const set = try self.rcuMembershipSet(c, name);
                try set.add(c.writer_participant, @bitCast(client));
                self.noteRcuChannelWrite(c);
            }
        }
    }

    /// Status modes for `client` in `name`, or null if not a member / no channel.
    pub fn memberModes(self: *World, name: []const u8, client: ClientId) ?MemberModes {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.members.get(client);
    }

    /// Resolve `nick`'s status modes within `name` by NICK (case-insensitive
    /// ASCII casemapping), without a ClientId in hand. Iterates the channel's
    /// member set and maps each member's ClientId back to its display nick via
    /// `client_nicks`. Returns null when the channel has no such member or no
    /// such channel. NOTE: only LOCAL members are stored in the world member
    /// set — remote mesh members live in the per-link route roster — so a remote
    /// sender will not resolve here; callers that must enforce policy against a
    /// remote actor consult the link roster separately.
    pub fn memberModesByNick(self: *World, name: []const u8, nick: []const u8) ?MemberModes {
        const channel = self.channels.getPtr(name) orelse return null;
        var it = channel.members.iterator();
        while (it.next()) |entry| {
            const member_nick = self.client_nicks.get(entry.key_ptr.*) orelse continue;
            if (std.ascii.eqlIgnoreCase(member_nick, nick)) return entry.value_ptr.*;
        }
        return null;
    }

    /// Whether `nick` is a (LOCAL) member of `name`, resolved by NICK
    /// (case-insensitive). Mirrors `memberModesByNick`'s resolution; see its note
    /// on remote members.
    pub fn isMemberByNick(self: *World, name: []const u8, nick: []const u8) bool {
        return self.memberModesByNick(name, nick) != null;
    }

    /// Set or clear one status mode for a member. Returns true if it changed.
    pub fn setMemberMode(
        self: *World,
        name: []const u8,
        client: ClientId,
        mode: MemberMode,
        on: bool,
    ) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const entry = channel.members.getEntry(client) orelse return error.NotOnChannel;
        const before = entry.value_ptr.contains(mode);
        if (on) entry.value_ptr.add(mode) else entry.value_ptr.remove(mode);
        return before != on;
    }

    /// Whether channel flag `mode` (i/m/n/t/s) is set. False if no such channel.
    pub fn channelHasFlag(self: *World, name: []const u8, mode: ChannelMode) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.modes.containsFlag(mode);
    }

    /// Whether an IRCX extended channel flag is set.
    pub fn channelHasExtFlag(self: *World, name: []const u8, flag: chanmode_ext.ExtChannelFlag) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.ext_modes.has(flag);
    }

    /// The channel's IRCX extended flag set (empty if no such channel).
    pub fn channelExtModes(self: *World, name: []const u8) chanmode_ext.ExtChannelFlags {
        const channel = self.channels.getPtr(name) orelse return chanmode_ext.ExtChannelFlags.empty();
        return channel.ext_modes;
    }

    /// Mark a channel REGISTERED (+r) on behalf of services, materializing an
    /// empty persistent channel if it does not exist yet. A +r channel survives
    /// when its last member leaves (see `part`/`removeClient`), so registering an
    /// unoccupied channel keeps it reserved. Clearing +r leaves the (possibly
    /// empty) channel in place; the next part/disconnect reclaims it normally.
    pub fn markRegistered(self: *World, name: []const u8, on: bool) std.mem.Allocator.Error!bool {
        const channel = try self.ensureChannel(name);
        const before = channel.ext_modes.has(.registered);
        if (on) channel.ext_modes.set(.registered) else channel.ext_modes.clear(.registered);
        return before != on;
    }

    /// Set or clear an IRCX extended channel flag. Returns true if it changed.
    pub fn setChannelExtFlag(self: *World, name: []const u8, flag: chanmode_ext.ExtChannelFlag, on: bool) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const before = channel.ext_modes.has(flag);
        if (on) channel.ext_modes.set(flag) else channel.ext_modes.clear(flag);
        return before != on;
    }

    /// Set or clear a channel flag mode (i/m/n/t/s). Returns true if it changed.
    pub fn setChannelFlag(self: *World, name: []const u8, mode: ChannelMode, on: bool) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const before = channel.modes.containsFlag(mode);
        switch (mode) {
            .invite_only => channel.modes.invite_only = on,
            .moderated => channel.modes.moderated = on,
            .no_external => channel.modes.no_external = on,
            .topic_ops => channel.modes.topic_ops = on,
            .secret => channel.modes.secret = on,
            .no_ctcp => channel.modes.no_ctcp = on,
            .no_notice => channel.modes.no_notice = on,
            .no_nick => channel.modes.no_nick = on,
            .free_invite => channel.modes.free_invite = on,
            .tls_only => channel.modes.tls_only = on,
            .mod_reg => channel.modes.mod_reg = on,
            .news_wire => channel.modes.news_wire = on,
            .oper_only => channel.modes.oper_only = on,
            .admin_only => channel.modes.admin_only = on,
            else => return error.UnsupportedMode, // not a flag mode (b/e/I/k/l)
        }
        return before != on;
    }

    /// Set (`key != null`) or clear the +k channel key. New key is heap-owned;
    /// any prior key is freed.
    pub fn setChannelKey(self: *World, name: []const u8, key: ?[]const u8) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const owned = if (key) |k| try self.allocator.dupe(u8, k) else null;
        if (channel.key) |old| self.allocator.free(old);
        channel.key = owned;
    }

    pub fn channelKey(self: *World, name: []const u8) ?[]const u8 {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.key;
    }

    /// Set (`limit != null`) or clear the +l member limit.
    pub fn setChannelLimit(self: *World, name: []const u8, limit: ?u32) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        channel.limit = limit;
    }

    pub fn channelLimit(self: *World, name: []const u8) ?u32 {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.limit;
    }

    /// The IRCX object id assigned to `name` at creation (null if no such channel).
    /// Unix-seconds creation time assigned to `name` at creation (null if no such
    /// channel; 0 if created before the server set a clock). IRCX CREATION prop.
    pub fn channelCreatedUnix(self: *World, name: []const u8) ?i64 {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.created_unix;
    }

    pub fn channelOid(self: *World, name: []const u8) ?u32 {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.oid;
    }

    /// IRCX CLONE: create `dst` as a clone of template channel `src`, copying the
    /// channel-level modes, limit, key, and ext flags (template-copy scope) and
    /// marking the new channel `+E` (clone) but not `+d` (a clone is not itself a
    /// cloneable template, so clones never recurse). Membership/topic/bans are NOT
    /// copied — the clone starts empty with a fresh OID. Returns false if `dst`
    /// already exists; `error.NoSuchChannel` if `src` does not.
    pub fn cloneChannel(self: *World, src: []const u8, dst: []const u8) WorldError!bool {
        if (self.channels.getPtr(src) == null) return error.NoSuchChannel;
        if (self.channels.contains(dst)) return false;

        // Snapshot the template fields BEFORE ensureChannel: getOrPut may rehash
        // and invalidate a pointer into the map.
        const tmpl = self.channels.getPtr(src).?;
        const modes = tmpl.modes;
        const limit = tmpl.limit;
        const private = tmpl.private;
        const hidden = tmpl.hidden;
        var ext = tmpl.ext_modes;
        const key_copy: ?[]u8 = if (tmpl.key) |k| try self.allocator.dupe(u8, k) else null;
        errdefer if (key_copy) |k| self.allocator.free(k);

        const clone = try self.ensureChannel(dst);
        clone.modes = modes;
        clone.limit = limit;
        clone.private = private;
        clone.hidden = hidden;
        ext.set(.clone);
        ext.clear(.cloneable);
        clone.ext_modes = ext;
        clone.key = key_copy;
        return true;
    }

    /// Rename a channel in place (draft/channel-rename): rekey the existing
    /// Channel value from `old` to `new`, preserving membership, modes, bans,
    /// topic, OID, and creation time. Returns false if `new` already exists;
    /// `error.NoSuchChannel` if `old` does not. The Channel carries no internal
    /// name, so a map rekey is a complete rename.
    pub fn renameChannel(self: *World, old: []const u8, new: []const u8) WorldError!bool {
        if (!self.channels.contains(old)) return error.NoSuchChannel;
        if (self.channels.contains(new)) return false;

        const oid = if (self.channels.getPtr(old)) |ch| ch.oid else 0;

        const new_key = try self.allocator.dupe(u8, new);
        errdefer self.allocator.free(new_key);
        const kv = self.channels.fetchRemove(old).?; // {key, value}
        self.channels.put(new_key, kv.value) catch |e| {
            // Re-insert under the original key so the channel is never lost.
            self.channels.put(kv.key, kv.value) catch {};
            return e;
        };
        self.allocator.free(kv.key);

        // Keep the RCU mirrors in step: re-key existence (same OID) and move the
        // membership set to the new folded key. Best-effort; the authoritative
        // store is `channels`.
        if (self.rcu_channels) |c| {
            self.rcuRenameMembership(c, old, new);
            // Existence: drop the old folded name only if it no longer maps to a
            // live channel (case-fold may coincide with `new`), then publish new.
            var ob: [foldBufLen]u8 = undefined;
            var nb: [foldBufLen]u8 = undefined;
            const of = foldName(old, &ob);
            const nf = foldName(new, &nb);
            if (!std.mem.eql(u8, of, nf)) {
                c.names.remove(c.writer_participant, old) catch {};
                self.noteRcuChannelWrite(c);
            }
            c.names.set(c.writer_participant, new, oid) catch {};
            self.noteRcuChannelWrite(c);
        }
        return true;
    }

    /// +p private channel flag.
    pub fn setPrivate(self: *World, name: []const u8, on: bool) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const before = channel.private;
        channel.private = on;
        return before != on;
    }
    pub fn isPrivate(self: *World, name: []const u8) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.private;
    }

    /// +h IRCX HIDDEN channel flag (omit from LIST).
    pub fn setHidden(self: *World, name: []const u8, on: bool) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const before = channel.hidden;
        channel.hidden = on;
        return before != on;
    }
    pub fn isHidden(self: *World, name: []const u8) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.hidden;
    }

    pub fn memberCount(self: *World, name: []const u8) usize {
        const channel = self.channels.getPtr(name) orelse return 0;
        return channel.members.count();
    }

    /// Add a +b ban mask. Returns true if newly added (false if already present).
    pub fn addBan(self: *World, name: []const u8, mask: []const u8, setter: []const u8, set_at: i64) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listAddMask(&channel.bans, mask, setter, set_at);
    }

    /// Remove a +b ban mask. Returns true if it existed.
    pub fn removeBan(self: *World, name: []const u8, mask: []const u8) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        for (channel.bans.items, 0..) |*b, idx| {
            if (std.mem.eql(u8, b.mask, mask)) {
                b.deinit(self.allocator);
                _ = channel.bans.orderedRemove(idx);
                return true;
            }
        }
        return false;
    }

    /// Ban masks for RPL_BANLIST, or null if no such channel.
    pub fn bansOf(self: *World, name: []const u8) ?[]const ListEntry {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.bans.items;
    }

    fn listAddMask(
        self: *World,
        list: *std.ArrayListUnmanaged(ListEntry),
        mask: []const u8,
        setter: []const u8,
        set_at: i64,
    ) WorldError!bool {
        for (list.items) |m| {
            if (std.mem.eql(u8, m.mask, mask)) return false;
        }
        // Cap channel list modes to bound memory and resist ban-list flooding.
        if (list.items.len >= self.max_list_entries) return error.ListFull;
        const entry = try ListEntry.init(self.allocator, mask, setter, set_at);
        errdefer {
            var rollback = entry;
            rollback.deinit(self.allocator);
        }
        try list.append(self.allocator, entry);
        return true;
    }

    fn listRemoveMask(self: *World, list: *std.ArrayListUnmanaged(ListEntry), mask: []const u8) bool {
        for (list.items, 0..) |*m, idx| {
            if (std.mem.eql(u8, m.mask, mask)) {
                m.deinit(self.allocator);
                _ = list.orderedRemove(idx);
                return true;
            }
        }
        return false;
    }

    fn listMatches(list: []const ListEntry, hostmask: []const u8) bool {
        for (list) |m| {
            if (listx.globMatch(m.mask, hostmask)) return true;
        }
        return false;
    }

    /// Client view used for extended-ban (`$a:`/`$r:`/`$g:`/`$c:`/`$~...`)
    /// evaluation. Re-exported from the extban parser so callers build one place.
    pub const BanContext = extban.ClientContext;

    /// Like `listMatches`, but each entry may be an extended ban. Plain masks
    /// fall through to a host glob against `ctx.host` (the full nick!user@host
    /// prefix), preserving classic +b/+e/+I/+Z behavior; `$`-prefixed entries
    /// match account/realname/country/channel/negation. Malformed `$` entries
    /// degrade to a literal host glob so a bad mask never silently disables a ban.
    fn listMatchesCtx(list: []const ListEntry, ctx: extban.ClientContext) bool {
        for (list) |m| {
            if (extban.parse(m.mask)) |matcher| {
                if (matcher.matches(ctx)) return true;
            } else |_| {
                if (listx.globMatch(m.mask, ctx.host)) return true;
            }
        }
        return false;
    }

    /// +e ban-exception list operations.
    pub fn addExempt(self: *World, name: []const u8, mask: []const u8, setter: []const u8, set_at: i64) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listAddMask(&channel.exempts, mask, setter, set_at);
    }
    pub fn removeExempt(self: *World, name: []const u8, mask: []const u8) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listRemoveMask(&channel.exempts, mask);
    }
    pub fn exemptsOf(self: *World, name: []const u8) ?[]const ListEntry {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.exempts.items;
    }
    pub fn isExempt(self: *World, name: []const u8, hostmask: []const u8) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return listMatches(channel.exempts.items, hostmask);
    }

    /// +I invite-exception list operations.
    pub fn addInvex(self: *World, name: []const u8, mask: []const u8, setter: []const u8, set_at: i64) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listAddMask(&channel.invex, mask, setter, set_at);
    }
    pub fn removeInvex(self: *World, name: []const u8, mask: []const u8) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listRemoveMask(&channel.invex, mask);
    }
    pub fn invexOf(self: *World, name: []const u8) ?[]const ListEntry {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.invex.items;
    }
    pub fn isInvexed(self: *World, name: []const u8, hostmask: []const u8) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return listMatches(channel.invex.items, hostmask);
    }

    /// +Z quiet (MUTE) list operations.
    pub fn addMute(self: *World, name: []const u8, mask: []const u8, setter: []const u8, set_at: i64) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listAddMask(&channel.mutes, mask, setter, set_at);
    }
    pub fn removeMute(self: *World, name: []const u8, mask: []const u8) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listRemoveMask(&channel.mutes, mask);
    }
    pub fn mutesOf(self: *World, name: []const u8) ?[]const ListEntry {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.mutes.items;
    }
    /// Whether `hostmask` is quieted (+Z) and not saved by a +e exempt.
    pub fn isMuted(self: *World, name: []const u8, hostmask: []const u8) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        if (listMatches(channel.exempts.items, hostmask)) return false;
        return listMatches(channel.mutes.items, hostmask);
    }

    /// +f forward target. `target == null` clears it. Owns a duped copy.
    pub fn setForward(self: *World, name: []const u8, target: ?[]const u8) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const owned = if (target) |t| try self.allocator.dupe(u8, t) else null;
        if (channel.forward) |old| self.allocator.free(old);
        channel.forward = owned;
    }
    /// The +f forward target for `name`, or null when unset / no such channel.
    pub fn forwardOf(self: *World, name: []const u8) ?[]const u8 {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.forward;
    }

    /// +j join-throttle config.
    pub fn setThrottle(self: *World, name: []const u8, joins: u16, secs: u32) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        channel.throttle_joins = joins;
        channel.throttle_secs = secs;
        channel.throttle_times.clearRetainingCapacity();
    }
    pub fn clearThrottle(self: *World, name: []const u8) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        channel.throttle_joins = 0;
        channel.throttle_secs = 0;
        channel.throttle_times.clearRetainingCapacity();
    }
    /// Returns the active throttle as {joins, secs}, or null when disabled.
    pub fn throttleOf(self: *World, name: []const u8) ?struct { joins: u16, secs: u32 } {
        const channel = self.channels.getPtr(name) orelse return null;
        if (channel.throttle_joins == 0) return null;
        return .{ .joins = channel.throttle_joins, .secs = channel.throttle_secs };
    }
    /// Admit one join against the +j window: prune expired timestamps, then deny
    /// (return false) without recording if the window is full, else record `now`
    /// and allow. No-op allow when throttle is disabled.
    pub fn throttleAdmit(self: *World, name: []const u8, now_ms: i64) bool {
        const channel = self.channels.getPtr(name) orelse return true;
        if (channel.throttle_joins == 0) return true;
        const window_ms: i64 = @as(i64, channel.throttle_secs) * 1000;
        // Prune timestamps outside the window (compact in place).
        var kept: usize = 0;
        for (channel.throttle_times.items) |ts| {
            if (now_ms - ts < window_ms) {
                channel.throttle_times.items[kept] = ts;
                kept += 1;
            }
        }
        channel.throttle_times.shrinkRetainingCapacity(kept);
        if (channel.throttle_times.items.len >= channel.throttle_joins) return false;
        channel.throttle_times.append(self.allocator, now_ms) catch return true; // alloc fail: fail-open
        return true;
    }

    /// Whether `hostmask` (nick!user@host) matches any +b entry (case-insensitive
    /// glob via listx.globMatch).
    pub fn isBanned(self: *World, name: []const u8, hostmask: []const u8) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        // A +e ban-exception match overrides any +b ban.
        if (listMatches(channel.exempts.items, hostmask)) return false;
        return listMatches(channel.bans.items, hostmask);
    }

    /// Extended-ban-aware +b check: `ctx.host` carries the full nick!user@host
    /// prefix (so plain masks behave exactly as `isBanned`), while `$`-typed
    /// bans match the richer context. A matching +e exception (also extban-aware)
    /// overrides the ban.
    pub fn isBannedCtx(self: *World, name: []const u8, ctx: extban.ClientContext) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        if (listMatchesCtx(channel.exempts.items, ctx)) return false;
        return listMatchesCtx(channel.bans.items, ctx);
    }

    /// Extended-ban-aware +Z quiet check (mirrors `isMuted`).
    pub fn isMutedCtx(self: *World, name: []const u8, ctx: extban.ClientContext) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        if (listMatchesCtx(channel.exempts.items, ctx)) return false;
        return listMatchesCtx(channel.mutes.items, ctx);
    }

    /// Extended-ban-aware +I invite-exception check (mirrors `isInvexed`).
    pub fn isInvexedCtx(self: *World, name: []const u8, ctx: extban.ClientContext) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return listMatchesCtx(channel.invex.items, ctx);
    }

    /// Record an INVITE so the target may bypass +i.
    pub fn addInvite(self: *World, name: []const u8, client: ClientId) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        try channel.invites.put(self.allocator, client, {});
    }

    /// Whether `client` holds a pending invite (does not consume it).
    pub fn hasInvite(self: *World, name: []const u8, client: ClientId) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.invites.contains(client);
    }

    /// Render the active channel flag modes as a "+imnt"-style string into `out`.
    pub fn channelModeString(self: *World, name: []const u8, out: []u8) []const u8 {
        const channel = self.channels.getPtr(name) orelse {
            if (out.len >= 1) {
                out[0] = '+';
                return out[0..1];
            }
            return out[0..0];
        };
        var n: usize = 0;
        if (n < out.len) {
            out[n] = '+';
            n += 1;
        }
        const flags = [_]struct { m: ChannelMode, c: u8 }{
            .{ .m = .invite_only, .c = 'i' },
            .{ .m = .moderated, .c = 'm' },
            .{ .m = .no_external, .c = 'n' },
            .{ .m = .topic_ops, .c = 't' },
            .{ .m = .secret, .c = 's' },
            .{ .m = .no_ctcp, .c = 'C' },
            .{ .m = .no_notice, .c = 'T' },
            .{ .m = .no_nick, .c = 'N' },
            .{ .m = .free_invite, .c = 'g' },
            .{ .m = .tls_only, .c = 'S' },
            .{ .m = .mod_reg, .c = 'M' },
            .{ .m = .news_wire, .c = 'W' },
            .{ .m = .oper_only, .c = 'O' },
            .{ .m = .admin_only, .c = 'A' },
        };
        for (flags) |f| {
            if (channel.modes.containsFlag(f.m) and n < out.len) {
                out[n] = f.c;
                n += 1;
            }
        }
        if (channel.private and n < out.len) {
            out[n] = 'p';
            n += 1;
        }
        if (channel.hidden and n < out.len) {
            out[n] = 'h';
            n += 1;
        }
        return out[0..n];
    }

    /// Part a channel, deleting it when the last member leaves.
    pub fn part(self: *World, name: []const u8, client: ClientId) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        if (!channel.members.remove(client)) return error.NotOnChannel;
        // Mirror the removal into the lock-free set (best-effort: the
        // authoritative store is `channel.members`).
        if (self.rcu_channels) |c| {
            if (rcuMembershipGet(c, name)) |set| {
                set.remove(c.writer_participant, @bitCast(client)) catch {};
                self.noteRcuChannelWrite(c);
            }
        }
        // A registered (+r) channel persists across empty: its config, topic,
        // and modes survive when the last member leaves. Unregistered channels
        // are ephemeral and reclaimed here.
        if (channel.members.count() == 0 and !channel.ext_modes.has(.registered)) {
            self.removeChannel(name);
        }
    }

    /// Whether `client` is a member of `name` (CASE-INSENSITIVE channel name).
    /// Reads the lock-free RCU membership set when active; falls back to the
    /// authoritative member map otherwise.
    pub fn isMember(self: *World, name: []const u8, client: ClientId) bool {
        if (self.rcu_channels) |c| {
            const p = rcuReaderParticipant(&c.domain, c.generation) catch {
                const channel = self.channels.getPtr(name) orelse return false;
                return channel.members.contains(client);
            };
            if (rcuMembershipGet(c, name)) |set|
                return set.contains(p, @bitCast(client));
            return false;
        }
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.members.contains(client);
    }

    /// Whether `name` exists (CASE-INSENSITIVE). Reads the lock-free RCU
    /// existence mirror when active; falls back to the case-sensitive map
    /// otherwise. `rcu_channels` is a pointer so this works through `*const`.
    pub fn channelExists(self: *const World, name: []const u8) bool {
        if (self.rcu_channels) |c| {
            const p = rcuReaderParticipant(&c.domain, c.generation) catch return self.channels.contains(name);
            return c.names.lookup(p, name) != null;
        }
        return self.channels.contains(name);
    }

    pub fn channelCount(self: *const World) usize {
        return self.channels.count();
    }

    /// Count of locally-owned registered nicks. The `nicks`/RCU map holds only
    /// LOCAL clients (remote mesh users are projected per-channel, never
    /// registered here), so this is the node-wide local user count. It reads
    /// through the lock-free RCU registry with a per-thread reader participant,
    /// so it is safe to call from ANY reactor shard — unlike iterating a single
    /// reactor's connection set, which only sees that shard's clients. Used by
    /// LUSERS/MAP so their counts are consistent regardless of which shard the
    /// querying client landed on under multithreading.
    pub fn localNickCount(self: *World) usize {
        const r = self.ensureRcuNicks() catch return self.nicks.count();
        const p = rcuReaderParticipant(&r.domain, r.generation) catch return self.nicks.count();
        return r.nicks.count(p);
    }

    /// Materialize an empty channel so remote mesh-owned list state (+b/+e/+I)
    /// can be stored before any local user joins it. Joining later still grants
    /// founder status because the member set is empty.
    pub fn ensureRemoteListChannel(self: *World, name: []const u8) WorldError!void {
        _ = try self.ensureChannel(name);
    }

    /// Read-only view of a channel for LIST.
    pub const ChannelView = struct {
        name: []const u8,
        members: usize,
        topic: []const u8,
        secret: bool,
        hidden: bool,
    };

    pub const ChannelViewIterator = struct {
        inner: CiStringHashMap(Channel).Iterator,

        pub fn next(self: *ChannelViewIterator) ?ChannelView {
            if (self.inner.next()) |entry| {
                return .{
                    .name = entry.key_ptr.*,
                    .members = entry.value_ptr.members.count(),
                    .topic = entry.value_ptr.topic orelse "",
                    .secret = entry.value_ptr.modes.secret,
                    .hidden = entry.value_ptr.hidden,
                };
            }
            return null;
        }
    };

    pub fn channelIterator(self: *World) ChannelViewIterator {
        return .{ .inner = self.channels.iterator() };
    }

    /// Fill `out` with the names of channels `client` is a member of (scan; no
    /// reverse index yet). Returns the count written, capped at `out.len`.
    /// Channel-name slices borrow from world storage and stay valid until the
    /// channel is removed.
    /// Count how many channels `client` is a member of (no buffer needed).
    pub fn channelCountOf(self: *World, client: ClientId) usize {
        var n: usize = 0;
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.members.contains(client)) n += 1;
        }
        return n;
    }

    pub fn channelsOf(self: *World, client: ClientId, out: [][]const u8) usize {
        var n: usize = 0;
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            if (n >= out.len) break;
            if (entry.value_ptr.members.contains(client)) {
                out[n] = entry.key_ptr.*;
                n += 1;
            }
        }
        return n;
    }

    pub fn memberIterator(self: *World, name: []const u8) ?MemberIterator {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.members.keyIterator();
    }

    pub fn setTopic(self: *World, name: []const u8, text: []const u8, setter: []const u8, set_at: i64) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        try channel.setTopic(text, setter, set_at);
    }

    pub fn topic(self: *const World, name: []const u8) ?[]const u8 {
        const channel = self.channels.get(name) orelse return null;
        return channel.topic;
    }

    pub fn topicInfo(self: *const World, name: []const u8) ?TopicInfo {
        const channel = self.channels.get(name) orelse return null;
        const text = channel.topic orelse return null;
        return .{
            .text = text,
            .setter = channel.topic_setter orelse "",
            .set_at = channel.topic_time,
        };
    }

    pub fn resolveMessageTarget(self: *World, target: []const u8) WorldError!MessageTarget {
        if (isChannelName(target)) {
            const entry = self.channels.getEntry(target) orelse return error.NoSuchChannel;
            return .{ .channel = entry.key_ptr.* };
        }

        if (self.findNick(target)) |client| {
            return .{ .nick = client };
        }
        return error.NoSuchNick;
    }

    /// Remove `client` from all registries and channels.
    pub fn removeClient(self: *World, client: ClientId) void {
        self.unregisterNick(client);

        while (true) {
            var empty_channel: ?[]const u8 = null;
            var it = self.channels.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.members.remove(client)) {
                    // Mirror the membership removal for channels that survive;
                    // removed channels have their whole set dropped below.
                    if (self.rcu_channels) |c| {
                        if (rcuMembershipGet(c, entry.key_ptr.*)) |set| {
                            set.remove(c.writer_participant, @bitCast(client)) catch {};
                            self.noteRcuChannelWrite(c);
                        }
                    }
                }
                // Registered (+r) channels persist across empty; only reclaim
                // ephemeral channels on the last member's disconnect.
                if (entry.value_ptr.members.count() == 0 and
                    !entry.value_ptr.ext_modes.has(.registered))
                {
                    empty_channel = entry.key_ptr.*;
                    break;
                }
            }
            if (empty_channel) |name| {
                self.removeChannel(name);
            } else {
                break;
            }
        }
    }

    fn ensureChannel(self: *World, name: []const u8) std.mem.Allocator.Error!*Channel {
        const entry = try self.channels.getOrPut(name);
        if (entry.found_existing) return entry.value_ptr;

        var owned_name: ?[]u8 = null;
        errdefer {
            if (owned_name) |owned| self.allocator.free(owned);
            self.channels.removeByPtr(entry.key_ptr);
        }
        owned_name = try self.allocator.dupe(u8, name);
        const oid = self.next_oid;

        // Activate + populate the RCU existence mirror BEFORE finalising the map
        // entry, so a mirror-alloc failure rolls back cleanly (errdefer above).
        const c = try self.ensureRcuChannels();
        try c.names.set(c.writer_participant, name, oid);
        self.noteRcuChannelWrite(c);
        errdefer {
            c.names.remove(c.writer_participant, name) catch {};
            self.noteRcuChannelWrite(c);
        }
        // Pre-create the (empty) membership set so isMember/joins are mirrored.
        _ = try self.rcuMembershipSet(c, name);

        entry.key_ptr.* = owned_name.?;
        entry.value_ptr.* = Channel.init(self.allocator);
        entry.value_ptr.oid = oid;
        entry.value_ptr.created_unix = self.clock_unix;
        self.next_oid +%= 1;
        return entry.value_ptr;
    }

    fn removeChannel(self: *World, name: []const u8) void {
        if (self.channels.getEntry(name)) |entry| {
            const owned_name = entry.key_ptr.*;
            entry.value_ptr.deinit();
            self.channels.removeByPtr(entry.key_ptr);
            // Tear down the RCU mirrors for this channel (existence + members).
            if (self.rcu_channels) |c| {
                c.names.remove(c.writer_participant, owned_name) catch {};
                self.noteRcuChannelWrite(c);
                self.rcuDropMembership(c, owned_name);
            }
            self.allocator.free(owned_name);
        }
    }
};

/// Max length of a name we case-fold into a stack buffer. Channel and nick
/// names are far shorter in practice; longer names truncate-fold (still
/// deterministic, only an academic edge case for absurd lengths).
const foldBufLen = 256;
const rcuAdvanceWriteInterval: usize = 64;
const rcuAdvancePasses: usize = 3;

fn advanceRcuDomainIfIdle(domain: *ebr.Domain) bool {
    if (!rcuDomainIdle(domain)) return false;
    var advanced = false;
    var pass: usize = 0;
    while (pass < rcuAdvancePasses) : (pass += 1) {
        if (!rcuDomainIdle(domain)) return advanced;
        advanced = domain.advance() or advanced;
    }
    return advanced;
}

fn rcuDomainIdle(domain: *ebr.Domain) bool {
    const n = domain.participant_count.load(.acquire);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (domain.participants[i].active.load(.acquire)) return false;
    }
    return true;
}

/// ASCII-lowercase `name` into `buf`, returning the folded slice. Used to key
/// the per-channel membership-set map case-insensitively, mirroring the
/// `CaseInsensitiveBytesContext` casemapping the RCU registries use.
fn foldName(name: []const u8, buf: []u8) []const u8 {
    const n = @min(name.len, buf.len);
    for (name[0..n], 0..) |ch, i| buf[i] = std.ascii.toLower(ch);
    return buf[0..n];
}

/// A valid channel name begins with a recognised channel sigil:
///   `#`  — standard (network-wide) channel
///   `&`  — local channel (RFC1459)
///   `%#` / `%&` — IRCX UTF8 channel (the `%` marks a UTF8-named variant)
/// The IRCX `^` UTF8→hex display form is intentionally NOT accepted yet (it needs
/// a transliteration layer; tracked separately).
pub fn isChannelName(name: []const u8) bool {
    if (name.len == 0) return false;
    return switch (name[0]) {
        '#', '&' => true,
        '%' => name.len >= 2 and (name[1] == '#' or name[1] == '&'),
        else => false,
    };
}

fn testClient(slot: u20) ClientId {
    return .{ .shard = 0, .slot = slot, .gen = 1 };
}

test "channelCountOf counts a client's memberships" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = testClient(1);
    try std.testing.expectEqual(@as(usize, 0), world.channelCountOf(a));
    _ = try world.join("#one", a);
    _ = try world.join("#two", a);
    _ = try world.join("#two", a); // re-join is a no-op
    try std.testing.expectEqual(@as(usize, 2), world.channelCountOf(a));
    _ = world.part("#one", a) catch {};
    try std.testing.expectEqual(@as(usize, 1), world.channelCountOf(a));
}

test "channel list modes are capped at max_list_entries" {
    var world = World.init(std.testing.allocator);
    world.max_list_entries = 2;
    defer world.deinit();
    _ = try world.join("#c", testClient(1)); // creates the channel

    try std.testing.expect(try world.addBan("#c", "a!*@*", "setter", 1));
    try std.testing.expect(try world.addBan("#c", "b!*@*", "setter", 2));
    try std.testing.expectError(error.ListFull, world.addBan("#c", "c!*@*", "setter", 3));
    // Each list mode has its own independent cap.
    try std.testing.expect(try world.addExempt("#c", "e1!*@*", "setter", 1));
    try std.testing.expect(try world.addExempt("#c", "e2!*@*", "setter", 2));
    try std.testing.expectError(error.ListFull, world.addExempt("#c", "e3!*@*", "setter", 3));
    // A duplicate is a no-op (false), not a cap error.
    try std.testing.expect(!try world.addBan("#c", "a!*@*", "setter", 4));
}

test "isChannelName accepts #, &, and %#/%& but not bare names or ^" {
    try std.testing.expect(isChannelName("#chan"));
    try std.testing.expect(isChannelName("&local"));
    try std.testing.expect(isChannelName("%#utf8"));
    try std.testing.expect(isChannelName("%&utf8local"));
    // Rejections: empty, plain nick, bare %, and the deferred ^ form.
    try std.testing.expect(!isChannelName(""));
    try std.testing.expect(!isChannelName("nick"));
    try std.testing.expect(!isChannelName("%"));
    try std.testing.expect(!isChannelName("%nope"));
    try std.testing.expect(!isChannelName("^hexchan"));
}

test "nick registry rejects collisions and supports lookup" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    const b = testClient(2);
    try world.registerNick("A", a);

    try std.testing.expectEqual(a, world.findNick("A").?);
    try std.testing.expectEqualStrings("A", world.nickOf(a).?);
    try std.testing.expectError(error.NickInUse, world.registerNick("A", b));

    world.unregisterNick(a);
    try std.testing.expectEqual(@as(?ClientId, null), world.findNick("A"));
    try std.testing.expectEqual(@as(?[]const u8, null), world.nickOf(a));
}

test "join part and membership cleanup" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    const b = testClient(2);

    try std.testing.expect(try world.join("#x", a));
    try std.testing.expect(!try world.join("#x", a));
    try std.testing.expect(try world.join("#x", b));
    try std.testing.expect(world.isMember("#x", a));
    try std.testing.expect(world.isMember("#x", b));
    try std.testing.expectEqual(@as(usize, 1), world.channelCount());

    try world.part("#x", a);
    try std.testing.expect(!world.isMember("#x", a));
    try std.testing.expect(world.isMember("#x", b));

    try world.part("#x", b);
    try std.testing.expect(!world.channelExists("#x"));
    try std.testing.expectEqual(@as(usize, 0), world.channelCount());
}

test "registered (+r) channels persist across empty; part and disconnect keep them" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    const b = testClient(2);

    try std.testing.expect(try world.join("#reg", a));
    try std.testing.expect(try world.join("#reg", b));
    _ = try world.setChannelExtFlag("#reg", .registered, true);

    // Last member parting must NOT reclaim a registered channel.
    try world.part("#reg", a);
    try world.part("#reg", b);
    try std.testing.expect(world.channelExists("#reg"));
    try std.testing.expect(world.channelHasExtFlag("#reg", .registered));

    // Disconnect path likewise preserves it.
    try std.testing.expect(try world.join("#reg", a));
    world.removeClient(a);
    try std.testing.expect(world.channelExists("#reg"));

    // An unregistered channel beside it is still reclaimed on empty.
    try std.testing.expect(try world.join("#eph", b));
    world.removeClient(b);
    try std.testing.expect(!world.channelExists("#eph"));
}

test "channels receive monotonic, stable, unique IRCX object ids" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    try std.testing.expect(try world.join("#first", a));
    try std.testing.expect(try world.join("#second", a));

    const oid1 = world.channelOid("#first").?;
    const oid2 = world.channelOid("#second").?;
    try std.testing.expectEqual(@as(u32, 1), oid1); // counter starts at 1
    try std.testing.expectEqual(@as(u32, 2), oid2);
    try std.testing.expect(oid1 != oid2);

    // OID is stable across further membership churn on the same channel.
    const b = testClient(2);
    try std.testing.expect(try world.join("#first", b));
    try std.testing.expectEqual(oid1, world.channelOid("#first").?);

    // Unknown channel has no OID.
    try std.testing.expect(world.channelOid("#nope") == null);
}

test "cloneChannel copies modes/limit/key and marks the clone +E with a fresh OID" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    try std.testing.expect(try world.join("#tmpl", a));
    try std.testing.expect(try world.setChannelFlag("#tmpl", .moderated, true));
    try world.setChannelLimit("#tmpl", 42);
    try world.setChannelKey("#tmpl", "sekret");
    try std.testing.expect(try world.setChannelExtFlag("#tmpl", .cloneable, true));
    const tmpl_oid = world.channelOid("#tmpl").?;

    try std.testing.expect(try world.cloneChannel("#tmpl", "#tmpl1"));

    // Modes/limit/key copied; clone is +E and not +d; OID is distinct; empty.
    try std.testing.expect(world.channelHasFlag("#tmpl1", .moderated));
    try std.testing.expectEqual(@as(?u32, 42), world.channelLimit("#tmpl1"));
    try std.testing.expect(world.channelHasExtFlag("#tmpl1", .clone));
    try std.testing.expect(!world.channelHasExtFlag("#tmpl1", .cloneable));
    try std.testing.expect(world.channelOid("#tmpl1").? != tmpl_oid);
    try std.testing.expectEqual(@as(usize, 0), world.memberCount("#tmpl1"));

    // Cloning onto an existing name is a no-op (false); cloning a missing source errors.
    try std.testing.expect(!try world.cloneChannel("#tmpl", "#tmpl1"));
    try std.testing.expectError(error.NoSuchChannel, world.cloneChannel("#nope", "#x"));
}

test "removeClient drops all channel memberships and nick ownership" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    const b = testClient(2);

    try world.registerNick("A", a);
    try world.registerNick("B", b);
    _ = try world.join("#x", a);
    _ = try world.join("#x", b);
    _ = try world.join("#y", a);

    world.removeClient(a);

    try std.testing.expectEqual(@as(?ClientId, null), world.findNick("A"));
    try std.testing.expect(!world.isMember("#x", a));
    try std.testing.expect(world.isMember("#x", b));
    try std.testing.expect(!world.channelExists("#y"));
}

test "message target resolution distinguishes channel and nick targets" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    try world.registerNick("A", a);
    _ = try world.join("#x", a);

    const channel = try world.resolveMessageTarget("#x");
    try std.testing.expectEqualStrings("#x", channel.channel);

    const nick = try world.resolveMessageTarget("A");
    try std.testing.expectEqual(a, nick.nick);

    try std.testing.expectError(error.NoSuchChannel, world.resolveMessageTarget("#missing"));
    try std.testing.expectError(error.NoSuchNick, world.resolveMessageTarget("missing"));
}

test "topics are owned and released" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    _ = try world.join("#x", a);
    try world.setTopic("#x", "first topic", "A!alice@localhost", 10);
    try std.testing.expectEqualStrings("first topic", world.topic("#x").?);
    var info = world.topicInfo("#x").?;
    try std.testing.expectEqualStrings("A!alice@localhost", info.setter);
    try std.testing.expectEqual(@as(i64, 10), info.set_at);
    try world.setTopic("#x", "second topic", "B!bob@localhost", 20);
    try std.testing.expectEqualStrings("second topic", world.topic("#x").?);
    info = world.topicInfo("#x").?;
    try std.testing.expectEqualStrings("B!bob@localhost", info.setter);
    try std.testing.expectEqual(@as(i64, 20), info.set_at);
}

test "first joiner founds the channel as operator; later joiners have no status" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const founder = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    const second = ClientId{ .shard = 0, .slot = 2, .gen = 1 };

    _ = try world.join("#x", founder);
    _ = try world.join("#x", second);

    try std.testing.expect(world.memberModes("#x", founder).?.contains(.founder));
    try std.testing.expect(world.memberModes("#x", founder).?.isOperator());
    try std.testing.expect(!world.memberModes("#x", second).?.contains(.founder));
    try std.testing.expectEqual(@as(u8, '!'), world.memberModes("#x", founder).?.highestPrefix());
    try std.testing.expectEqual(@as(u8, 0), world.memberModes("#x", second).?.highestPrefix());
}

test "setMemberMode adds and removes status and reports change" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    const b = ClientId{ .shard = 0, .slot = 2, .gen = 1 };
    _ = try world.join("#x", a); // a founds (op)
    _ = try world.join("#x", b);

    try std.testing.expect(try world.setMemberMode("#x", b, .voice, true));
    try std.testing.expect(world.memberModes("#x", b).?.contains(.voice));
    // Idempotent set reports no change.
    try std.testing.expect(!(try world.setMemberMode("#x", b, .voice, true)));
    try std.testing.expect(try world.setMemberMode("#x", b, .voice, false));
    try std.testing.expect(!world.memberModes("#x", b).?.contains(.voice));

    try std.testing.expectError(error.NotOnChannel, world.setMemberMode("#x", ClientId{ .shard = 0, .slot = 9, .gen = 1 }, .op, true));
    try std.testing.expect(world.memberModes("#nope", a) == null);
}

test "memberModesByNick / isMemberByNick resolve local members case-insensitively" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    const b = ClientId{ .shard = 0, .slot = 2, .gen = 1 };
    try world.registerNick("Alice", a); // founder of #x
    try world.registerNick("Bob", b);
    _ = try world.join("#x", a);
    _ = try world.join("#x", b);
    try std.testing.expect(try world.setMemberMode("#x", b, .voice, true));

    // Founder a resolves with founder/operator status; case-insensitive lookup.
    try std.testing.expect(world.memberModesByNick("#x", "alice").?.isOperator());
    try std.testing.expect(world.isMemberByNick("#x", "ALICE"));
    // b resolves with voice and is a member but not operator.
    try std.testing.expect(world.memberModesByNick("#x", "bob").?.contains(.voice));
    try std.testing.expect(!world.memberModesByNick("#x", "bob").?.isOperator());
    try std.testing.expect(world.isMemberByNick("#x", "Bob"));

    // A nick not in the channel — and an unknown channel — both resolve to null.
    try std.testing.expect(world.memberModesByNick("#x", "carol") == null);
    try std.testing.expect(!world.isMemberByNick("#x", "carol"));
    try std.testing.expect(world.memberModesByNick("#nope", "alice") == null);
}

test "channel key, limit, bans, and invites with ownership" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    const b = ClientId{ .shard = 0, .slot = 2, .gen = 1 };
    _ = try world.join("#x", a);

    // Key: set, replace (frees old), clear (frees).
    try world.setChannelKey("#x", "first");
    try std.testing.expectEqualStrings("first", world.channelKey("#x").?);
    try world.setChannelKey("#x", "second");
    try std.testing.expectEqualStrings("second", world.channelKey("#x").?);
    try world.setChannelKey("#x", null);
    try std.testing.expect(world.channelKey("#x") == null);

    // Limit.
    try std.testing.expect(world.channelLimit("#x") == null);
    try world.setChannelLimit("#x", 42);
    try std.testing.expectEqual(@as(?u32, 42), world.channelLimit("#x"));

    // Bans: add (dedup), match (glob, case-insensitive), remove.
    try std.testing.expect(try world.addBan("#x", "bad!*@*", "setter", 1));
    try std.testing.expect(!(try world.addBan("#x", "bad!*@*", "setter", 1))); // dup
    try std.testing.expect(world.isBanned("#x", "BAD!user@host"));
    try std.testing.expect(!world.isBanned("#x", "good!user@host"));
    try std.testing.expectEqual(@as(usize, 1), world.bansOf("#x").?.len);
    try std.testing.expect(try world.removeBan("#x", "bad!*@*"));
    try std.testing.expect(!world.isBanned("#x", "BAD!user@host"));

    // +e exemption overrides a +b ban; +I invite-exception list is independent.
    try std.testing.expect(try world.addBan("#x", "bad!*@*", "setter", 2));
    try std.testing.expect(world.isBanned("#x", "bad!u@h"));
    try std.testing.expect(try world.addExempt("#x", "bad!vip@*", "setter", 3));
    try std.testing.expect(!world.isBanned("#x", "bad!vip@h")); // exempt wins
    try std.testing.expect(world.isBanned("#x", "bad!other@h")); // still banned
    try std.testing.expectEqual(@as(usize, 1), world.exemptsOf("#x").?.len);
    try std.testing.expect(try world.removeExempt("#x", "bad!vip@*"));
    try std.testing.expect(world.isBanned("#x", "bad!vip@h")); // ban back in force
    try std.testing.expect(try world.addInvex("#x", "friend!*@*", "setter", 4));
    try std.testing.expect(world.isInvexed("#x", "FRIEND!u@h"));
    try std.testing.expectEqual(@as(usize, 1), world.invexOf("#x").?.len);

    // Invites.
    try std.testing.expect(!world.hasInvite("#x", b));
    try world.addInvite("#x", b);
    try std.testing.expect(world.hasInvite("#x", b));

    // memberCount tracks membership.
    try std.testing.expectEqual(@as(usize, 1), world.memberCount("#x"));
    try std.testing.expectError(error.NoSuchChannel, world.setChannelKey("#nope", "k"));
}

test "renameChannel rekeys in place, preserving membership and bans" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    _ = try world.join("#old", a);
    try world.setTopic("#old", "hello", "setter", 1);
    try std.testing.expect(try world.addBan("#old", "bad!*@*", "setter", 1));

    // Rename moves everything to the new key.
    try std.testing.expect(try world.renameChannel("#old", "#new"));
    try std.testing.expect(!world.channelExists("#old"));
    try std.testing.expect(world.channelExists("#new"));
    try std.testing.expect(world.isMember("#new", a));
    try std.testing.expect(world.isBanned("#new", "bad!u@h"));

    // Renaming onto an existing channel fails (false); missing source errors.
    const b = ClientId{ .shard = 0, .slot = 2, .gen = 1 };
    _ = try world.join("#taken", b);
    try std.testing.expect(!(try world.renameChannel("#new", "#taken")));
    try std.testing.expectError(error.NoSuchChannel, world.renameChannel("#ghost", "#x"));
}

test "extended bans match account, realname, channel, and negation" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    _ = try world.join("#x", a);

    // Plain mask via the ctx path still globs the host prefix (back-compat).
    try std.testing.expect(try world.addBan("#x", "bad!*@*", "setter", 1));
    try std.testing.expect(world.isBannedCtx("#x", .{ .host = "bad!u@h" }));
    try std.testing.expect(!world.isBannedCtx("#x", .{ .host = "ok!u@h" }));
    try std.testing.expect(try world.removeBan("#x", "bad!*@*"));

    // $a: account ban.
    try std.testing.expect(try world.addBan("#x", "$a:spammer", "setter", 2));
    try std.testing.expect(world.isBannedCtx("#x", .{ .account = "spammer", .host = "x!y@z" }));
    try std.testing.expect(!world.isBannedCtx("#x", .{ .account = "good", .host = "x!y@z" }));
    // Unauthenticated client never matches an account ban.
    try std.testing.expect(!world.isBannedCtx("#x", .{ .host = "x!y@z" }));

    // $r: realname glob; $e exemption (also extban-aware) overrides.
    try std.testing.expect(try world.addBan("#x", "$r:*bot*", "setter", 3));
    try std.testing.expect(world.isBannedCtx("#x", .{ .realname = "evil bot 9000", .host = "x!y@z" }));
    try std.testing.expect(try world.addExempt("#x", "$a:trusted", "setter", 4));
    try std.testing.expect(!world.isBannedCtx("#x", .{ .account = "trusted", .realname = "evil bot", .host = "x!y@z" }));

    // $c: channel ban — banned when present in #secret.
    try std.testing.expect(try world.addBan("#x", "$c:#secret", "setter", 5));
    const chans = [_][]const u8{"#secret"};
    try std.testing.expect(world.isBannedCtx("#x", .{ .host = "n!u@h", .channels = &chans }));
    // $~a: negated account ban (matches everyone NOT logged in as alice).
    try std.testing.expect(try world.addMute("#x", "$~a:alice", "setter", 6));
    try std.testing.expect(!world.isMutedCtx("#x", .{ .account = "alice", .host = "x!y@z" }));
    try std.testing.expect(world.isMutedCtx("#x", .{ .account = "bob", .host = "x!y@z" }));
}

test "channel flag modes set, query, and render" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    _ = try world.join("#x", a);

    try std.testing.expect(!world.channelHasFlag("#x", .moderated));
    try std.testing.expect(try world.setChannelFlag("#x", .moderated, true));
    try std.testing.expect(!(try world.setChannelFlag("#x", .topic_ops, true)));
    try std.testing.expect(world.channelHasFlag("#x", .moderated));
    // Idempotent set reports no change.
    try std.testing.expect(!(try world.setChannelFlag("#x", .moderated, true)));

    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("+mnt", world.channelModeString("#x", &buf));

    try std.testing.expect(try world.setChannelFlag("#x", .moderated, false));
    try std.testing.expectEqualStrings("+nt", world.channelModeString("#x", &buf));
    try std.testing.expectError(error.NoSuchChannel, world.setChannelFlag("#nope", .secret, true));
}

test "+Z quiet (MUTE) list: add, match, exempt override, remove" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    _ = try world.join("#z", a);

    // Empty list mutes nobody.
    try std.testing.expect(!world.isMuted("#z", "loud!u@h"));

    // Add (dedup), glob + case-insensitive match.
    try std.testing.expect(try world.addMute("#z", "loud!*@*", "setter", 1));
    try std.testing.expect(!(try world.addMute("#z", "loud!*@*", "setter", 1))); // dup
    try std.testing.expect(world.isMuted("#z", "LOUD!user@host"));
    try std.testing.expect(!world.isMuted("#z", "quiet!user@host"));
    try std.testing.expectEqual(@as(usize, 1), world.mutesOf("#z").?.len);

    // A +e exempt overrides a +Z quiet, mirroring +b/+e semantics.
    try std.testing.expect(try world.addExempt("#z", "loud!vip@*", "setter", 2));
    try std.testing.expect(!world.isMuted("#z", "loud!vip@host")); // exempt wins
    try std.testing.expect(world.isMuted("#z", "loud!other@host")); // still muted

    // Remove returns to un-muted.
    try std.testing.expect(try world.removeMute("#z", "loud!*@*"));
    try std.testing.expect(!world.isMuted("#z", "loud!other@host"));
    try std.testing.expectError(error.NoSuchChannel, world.addMute("#nope", "x!*@*", "setter", 1));
}

test "+j join throttle: token bucket admits up to N per window, then denies" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    _ = try world.join("#j", a);

    // Disabled by default: every join admitted, throttleOf is null.
    try std.testing.expect(world.throttleOf("#j") == null);
    try std.testing.expect(world.throttleAdmit("#j", 0));

    // Configure 2 joins per 10 seconds.
    try world.setThrottle("#j", 2, 10);
    const cfg = world.throttleOf("#j").?;
    try std.testing.expectEqual(@as(u16, 2), cfg.joins);
    try std.testing.expectEqual(@as(u32, 10), cfg.secs);

    // First two joins in the window are admitted; the third is denied.
    try std.testing.expect(world.throttleAdmit("#j", 1000));
    try std.testing.expect(world.throttleAdmit("#j", 2000));
    try std.testing.expect(!world.throttleAdmit("#j", 3000));

    // After the window elapses, old timestamps prune and joins admit again.
    try std.testing.expect(world.throttleAdmit("#j", 13000)); // 1000ms entry expired
    try std.testing.expect(world.throttleAdmit("#j", 13500)); // 2000ms entry expired
    try std.testing.expect(!world.throttleAdmit("#j", 14000)); // window full again

    // Clearing disables the throttle entirely.
    try world.clearThrottle("#j");
    try std.testing.expect(world.throttleOf("#j") == null);
    try std.testing.expect(world.throttleAdmit("#j", 99999));
    try std.testing.expectError(error.NoSuchChannel, world.setThrottle("#nope", 1, 1));
}

test "+f forward target: set (owned dupe), read, replace, clear" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    _ = try world.join("#f", a);

    try std.testing.expect(world.forwardOf("#f") == null);
    try world.setForward("#f", "#overflow");
    try std.testing.expectEqualStrings("#overflow", world.forwardOf("#f").?);
    // Replace frees the old dupe and stores the new one.
    try world.setForward("#f", "#lobby");
    try std.testing.expectEqualStrings("#lobby", world.forwardOf("#f").?);
    // Clear frees the dupe.
    try world.setForward("#f", null);
    try std.testing.expect(world.forwardOf("#f") == null);
    try std.testing.expectError(error.NoSuchChannel, world.setForward("#nope", "#x"));
}

test "channelsOf lists a client's channels" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    const b = ClientId{ .shard = 0, .slot = 2, .gen = 1 };
    _ = try world.join("#x", a);
    _ = try world.join("#y", a);
    _ = try world.join("#x", b);

    var buf: [8][]const u8 = undefined;
    const n = world.channelsOf(a, &buf);
    try std.testing.expectEqual(@as(usize, 2), n);
    // both #x and #y present (order is map-dependent)
    var seen_x = false;
    var seen_y = false;
    for (buf[0..n]) |c| {
        if (std.mem.eql(u8, c, "#x")) seen_x = true;
        if (std.mem.eql(u8, c, "#y")) seen_y = true;
    }
    try std.testing.expect(seen_x and seen_y);
    try std.testing.expectEqual(@as(usize, 1), world.channelsOf(b, &buf));
}

const MtCtx = struct {
    world: *World,
    client: ClientId,
    nick: []const u8,
    iters: u64,

    fn writer(ctx: *MtCtx) void {
        // Register once, then hammer join/part on a shared channel — every
        // mutation (and its allocation) under the exclusive write lock.
        ctx.world.lockWrite();
        ctx.world.registerNick(ctx.nick, ctx.client) catch {};
        ctx.world.unlockWrite();
        var i: u64 = 0;
        while (i < ctx.iters) : (i += 1) {
            ctx.world.lockWrite();
            _ = ctx.world.join("#mt", ctx.client) catch {};
            ctx.world.part("#mt", ctx.client) catch {};
            ctx.world.unlockWrite();
        }
    }

    fn reader(ctx: *MtCtx) void {
        var i: u64 = 0;
        while (i < ctx.iters) : (i += 1) {
            ctx.world.lockRead();
            std.mem.doNotOptimizeAway(ctx.world.nickOf(ctx.client));
            ctx.world.unlockRead();
        }
    }
};

test "World mutations + reads are race-free under its RwLock" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const writers = 4;
    const iters: u64 = 3000;
    var nick_bufs: [writers][8]u8 = undefined;
    var ctxs: [writers]MtCtx = undefined;
    for (0..writers) |i| {
        const nick = std.fmt.bufPrint(&nick_bufs[i], "n{d}", .{i}) catch unreachable;
        ctxs[i] = .{
            .world = &world,
            .client = ClientId{ .shard = 0, .slot = @intCast(i + 1), .gen = 1 },
            .nick = nick,
            .iters = iters,
        };
    }

    var threads: [writers * 2]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |t| t.join();
    for (0..writers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, MtCtx.writer, .{&ctxs[i]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (0..writers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, MtCtx.reader, .{&ctxs[i]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (threads[0..spawned]) |t| t.join();

    // Each writer registered exactly one (distinct) nick; all joins were paired
    // with parts, so the shared channel ends empty. Consistency proves the lock
    // serialised every mutation without corruption.
    try std.testing.expectEqual(@as(usize, writers), world.nicks.count());
    try std.testing.expectEqual(@as(usize, 0), world.memberCount("#mt"));
    for (0..writers) |i| {
        try std.testing.expectEqualStrings(ctxs[i].nick, world.nickOf(ctxs[i].client).?);
    }
}

test "RCU nick mirror matches the authoritative map" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    // Activate the mirror before registering so registerNick keeps it in sync.
    _ = try world.ensureRcuNicks();

    const alice: ClientId = .{ .shard = 0, .slot = 1, .gen = 1 };
    const bob: ClientId = .{ .shard = 0, .slot = 2, .gen = 1 };
    try world.registerNick("Alice", alice);
    try world.registerNick("Bob", bob);

    // Hits agree with the authoritative map (exact case, apples-to-apples).
    try std.testing.expectEqual(world.findNick("Alice"), try world.findNickRcu("Alice"));
    try std.testing.expectEqual(world.findNick("Bob"), try world.findNickRcu("Bob"));
    try std.testing.expectEqual(@as(?ClientId, alice), try world.findNickRcu("Alice"));

    // Miss is a miss in both.
    try std.testing.expect((try world.findNickRcu("nobody")) == null);

    // Unregister keeps the mirror in sync.
    world.unregisterNick(alice);
    try std.testing.expect((try world.findNickRcu("Alice")) == null);
    try std.testing.expectEqual(@as(?ClientId, bob), try world.findNickRcu("Bob"));

    // Case-insensitive RCU lookup (an intended refinement over the case-sensitive
    // authoritative map; reconciled at the live flip).
    try std.testing.expectEqual(@as(?ClientId, bob), try world.findNickRcu("bob"));
}

test "findNick is case-insensitive once the RCU mirror is live" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const alice: ClientId = .{ .shard = 0, .slot = 1, .gen = 1 };
    try world.registerNick("Alice", alice); // activates the mirror

    // Every casing of the registered nick resolves to the same owner.
    try std.testing.expectEqual(@as(?ClientId, alice), world.findNick("Alice"));
    try std.testing.expectEqual(@as(?ClientId, alice), world.findNick("alice"));
    try std.testing.expectEqual(@as(?ClientId, alice), world.findNick("ALICE"));
    try std.testing.expectEqual(@as(?ClientId, alice), world.findNick("aLiCe"));
    // Unknown nick still misses.
    try std.testing.expectEqual(@as(?ClientId, null), world.findNick("bob"));
}

test "nick collisions are case-insensitive (Alice then alice collides)" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const alice: ClientId = .{ .shard = 0, .slot = 1, .gen = 1 };
    const mallory: ClientId = .{ .shard = 0, .slot = 2, .gen = 1 };

    try world.registerNick("Alice", alice);
    // A different client cannot take any casing of an in-use nick.
    try std.testing.expectError(error.NickInUse, world.registerNick("alice", mallory));
    try std.testing.expectError(error.NickInUse, world.registerNick("ALICE", mallory));

    // The original owner may re-assert / change the case of their own nick.
    try world.registerNick("ALICE", alice);
    try std.testing.expectEqualStrings("ALICE", world.nickOf(alice).?);
    try std.testing.expectEqual(@as(?ClientId, alice), world.findNick("alice"));

    // Releasing frees the (case-insensitive) name for someone else.
    world.unregisterNick(alice);
    try world.registerNick("alice", mallory);
    try std.testing.expectEqual(@as(?ClientId, mallory), world.findNick("Alice"));
}

test "channelExists mirror matches the authoritative map (case-insensitive)" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    try std.testing.expect(!world.channelExists("#room"));

    _ = try world.join("#Room", a); // creates the channel + activates mirror

    // Existence is case-insensitive and agrees across casings.
    try std.testing.expect(world.channelExists("#Room"));
    try std.testing.expect(world.channelExists("#room"));
    try std.testing.expect(world.channelExists("#ROOM"));
    try std.testing.expect(!world.channelExists("#other"));

    // Emptying the channel reclaims it from the mirror too.
    try world.part("#room", a);
    try std.testing.expect(!world.channelExists("#Room"));
    try std.testing.expect(!world.channelExists("#room"));
}

test "isMember mirror matches authoritative membership (case-insensitive)" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    const b = testClient(2);

    _ = try world.join("#Chan", a);
    _ = try world.join("#chan", b); // same channel, different casing

    // Both members are visible through any casing of the channel name.
    try std.testing.expect(world.isMember("#Chan", a));
    try std.testing.expect(world.isMember("#CHAN", a));
    try std.testing.expect(world.isMember("#chan", b));
    try std.testing.expect(!world.isMember("#chan", testClient(9)));
    try std.testing.expect(!world.isMember("#nope", a));

    // Part removes from the mirror; the other member stays.
    try world.part("#chan", a);
    try std.testing.expect(!world.isMember("#Chan", a));
    try std.testing.expect(world.isMember("#Chan", b));

    // Disconnect path clears membership too.
    world.removeClient(b);
    try std.testing.expect(!world.channelExists("#chan"));
    try std.testing.expect(!world.isMember("#chan", b));
}

test "registered channel keeps RCU membership across empty, then reclaims" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    _ = try world.join("#reg", a);
    _ = try world.setChannelExtFlag("#reg", .registered, true);

    // Last member leaves: registered channel persists (mirror still says exists),
    // but the member is gone from the membership mirror.
    try world.part("#reg", a);
    try std.testing.expect(world.channelExists("#reg"));
    try std.testing.expect(!world.isMember("#reg", a));

    // Re-join repopulates the mirror.
    _ = try world.join("#REG", a);
    try std.testing.expect(world.isMember("#reg", a));
}

test "renameChannel keeps RCU existence and membership mirrors in step" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    _ = try world.join("#old", a);
    try std.testing.expect(try world.renameChannel("#old", "#new"));

    try std.testing.expect(!world.channelExists("#old"));
    try std.testing.expect(world.channelExists("#new"));
    try std.testing.expect(world.channelExists("#NEW"));
    try std.testing.expect(world.isMember("#new", a));
    try std.testing.expect(!world.isMember("#old", a));
}
