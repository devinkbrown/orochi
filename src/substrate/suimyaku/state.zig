//! IRC network-state CRDTs for the LADON mesh.
//!
//! This module models the daemon-visible IRC graph as mergeable state:
//! users, nick claims, channels, memberships, modes, masks, and topics. It is
//! intentionally pure state logic so Deterministic Ocean can replay and merge
//! replicas without I/O or wall-clock reads.
const std = @import("std");

const clock = @import("clock.zig");
const crdt = @import("crdt.zig");

pub const Hlc = clock.Hlc;
pub const Dot = crdt.Dot;
pub const OrSet = crdt.OrSet;
pub const LwwRegister = crdt.LwwRegister;

pub const Authority = u16;
pub const NodeId = u64;
pub const ReplicaId = u64;

pub const Uid = InlineString(32);
pub const Nick = InlineString(64);
pub const ChannelName = InlineString(64);
pub const ModeParam = InlineString(128);
pub const Mask = InlineString(160);
pub const TopicText = InlineString(390);
pub const ShortText = InlineString(96);

/// Fixed-capacity, value-comparable IRC text.
pub fn InlineString(comptime max_len: usize) type {
    return struct {
        const Self = @This();

        bytes: [max_len]u8 = [_]u8{0} ** max_len,
        len: u16 = 0,

        pub const Error = error{StringTooLong};

        pub fn init(input: []const u8) Error!Self {
            if (input.len > max_len) return error.StringTooLong;
            var out = Self{};
            if (input.len != 0) {
                @memcpy(out.bytes[0..input.len], input);
            }
            out.len = @intCast(input.len);
            return out;
        }

        pub fn initLower(input: []const u8) Error!Self {
            var out = try Self.init(input);
            for (out.bytes[0..out.len]) |*byte| {
                if (byte.* >= 'A' and byte.* <= 'Z') byte.* += 'a' - 'A';
            }
            return out;
        }

        pub fn empty() Self {
            return .{};
        }

        pub fn asSlice(self: *const Self) []const u8 {
            return self.bytes[0..self.len];
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.len == b.len and std.mem.eql(u8, a.asSlice(), b.asSlice());
        }

        pub fn lessThan(a: Self, b: Self) bool {
            return std.mem.order(u8, a.asSlice(), b.asSlice()) == .lt;
        }
    };
}

pub const UserProfile = struct {
    nick: Nick = Nick.empty(),
    account: ShortText = ShortText.empty(),
    realname: ShortText = ShortText.empty(),
};

pub const PresenceLease = struct {
    expires_at_ms: u64 = 0,
    tombstoned: bool = false,
};

pub const NickClaim = struct {
    nick: Nick,
    uid: Uid,
    authority: Authority,
    hlc: Hlc,
    node_id: NodeId,
};

pub const NickOutcome = enum {
    absent,
    keep_nick,
    rename_to_uid,
};

pub const NickResolution = struct {
    outcome: NickOutcome,
    display: Nick,
    winner_uid: ?Uid,
};

pub const ChannelRoot = struct {
    name: ChannelName,
    birth_hlc: Hlc = .{},
    has_birth: bool = false,
    authority: Authority = 0,
    node_id: NodeId = 0,
};

pub const MembershipKey = struct {
    channel: ChannelName,
    uid: Uid,
    session: u64,
};

pub const PrefixModeKey = struct {
    channel: ChannelName,
    uid: Uid,
    mode: u8,
};

pub const AuthToggle = struct {
    enabled: bool = false,
    authority: Authority = 0,
    hlc: Hlc = .{},
    node_id: NodeId = 0,

    pub fn merge(self: *AuthToggle, other: AuthToggle) void {
        if (authToggleWins(other, self.*)) self.* = other;
    }
};

pub const BooleanModePolicy = enum {
    add_wins,
    remove_wins,
};

pub const BooleanModeKey = struct {
    channel: ChannelName,
    mode: u8,
};

pub const CausalToggleRegister = struct {
    policy: BooleanModePolicy,
    enabled: bool = false,
    hlc: Hlc = .{},
    node_id: NodeId = 0,

    pub fn init(policy: BooleanModePolicy) CausalToggleRegister {
        return .{ .policy = policy };
    }

    pub fn set(self: *CausalToggleRegister, enabled: bool, hlc: Hlc, node_id: NodeId) void {
        self.merge(.{
            .policy = self.policy,
            .enabled = enabled,
            .hlc = hlc,
            .node_id = node_id,
        });
    }

    pub fn merge(self: *CausalToggleRegister, other: CausalToggleRegister) void {
        if (toggleWins(other, self.*)) self.* = other;
    }
};

pub const ParamModeKey = struct {
    channel: ChannelName,
    mode: u8,
};

pub const ParamModeValue = struct {
    value: ModeParam,
    authority: Authority,
};

pub const BanKind = enum(u8) {
    ban,
    except,
    invex,
};

pub const BanKey = struct {
    channel: ChannelName,
    kind: BanKind,
    mask: Mask,
};

pub const BanMetadata = struct {
    setter: Uid,
    reason: ShortText = ShortText.empty(),
};

pub const TopicValue = struct {
    text: TopicText,
    setter: Uid,
    hlc: Hlc,
};

const UserEntry = struct {
    uid: Uid,
    profile: LwwRegister(UserProfile) = LwwRegister(UserProfile).init(),
    presence: LwwRegister(PresenceLease) = LwwRegister(PresenceLease).init(),
};

const PrefixModeEntry = struct {
    key: PrefixModeKey,
    toggle: AuthToggle,
};

const BooleanModeEntry = struct {
    key: BooleanModeKey,
    toggle: CausalToggleRegister,
};

const ParamModeEntry = struct {
    key: ParamModeKey,
    register: LwwRegister(ParamModeValue) = LwwRegister(ParamModeValue).init(),
};

const BanMetadataEntry = struct {
    key: BanKey,
    register: LwwRegister(BanMetadata) = LwwRegister(BanMetadata).init(),
};

const TopicEntry = struct {
    channel: ChannelName,
    register: LwwRegister(TopicValue) = LwwRegister(TopicValue).init(),
};

/// Complete IRC graph for one LADON replica.
pub const NetworkState = struct {
    const Self = @This();
    const MembershipSet = OrSet(MembershipKey);
    const BanSet = OrSet(BanKey);

    allocator: std.mem.Allocator,
    replica_id: ReplicaId,
    node_id: NodeId,
    users: std.ArrayList(UserEntry) = .empty,
    // Pruned on every insert/merge to the best claim per UID contender. Full
    // causal-stability-gated pruning is the follow-up once mesh stability
    // watermarks are available.
    nick_claims: std.ArrayList(NickClaim) = .empty,
    channels: std.ArrayList(ChannelRoot) = .empty,
    memberships: MembershipSet,
    prefix_modes: std.ArrayList(PrefixModeEntry) = .empty,
    boolean_modes: std.ArrayList(BooleanModeEntry) = .empty,
    param_modes: std.ArrayList(ParamModeEntry) = .empty,
    bans: BanSet,
    ban_metadata: std.ArrayList(BanMetadataEntry) = .empty,
    topics: std.ArrayList(TopicEntry) = .empty,

    pub fn init(allocator: std.mem.Allocator, replica_id: ReplicaId, node_id: NodeId) Self {
        return .{
            .allocator = allocator,
            .replica_id = replica_id,
            .node_id = node_id,
            .memberships = MembershipSet.init(allocator, replica_id),
            .bans = BanSet.init(allocator, replica_id),
        };
    }

    pub fn deinit(self: *Self) void {
        self.users.deinit(self.allocator);
        self.nick_claims.deinit(self.allocator);
        self.channels.deinit(self.allocator);
        self.memberships.deinit();
        self.prefix_modes.deinit(self.allocator);
        self.boolean_modes.deinit(self.allocator);
        self.param_modes.deinit(self.allocator);
        self.bans.deinit();
        self.ban_metadata.deinit(self.allocator);
        self.topics.deinit(self.allocator);
        self.* = Self.init(self.allocator, self.replica_id, self.node_id);
    }

    pub fn upsertUser(self: *Self, uid: Uid, profile: UserProfile, hlc: Hlc, authority: Authority) !void {
        const entry = try self.ensureUser(uid);
        _ = authority;
        _ = entry.profile.set(profile, hlc.toU64(), self.node_id);
    }

    pub fn setPresence(self: *Self, uid: Uid, lease: PresenceLease, hlc: Hlc) !void {
        const entry = try self.ensureUser(uid);
        _ = entry.presence.set(lease, hlc.toU64(), self.node_id);
    }

    pub fn claimNick(self: *Self, nick: Nick, uid: Uid, authority: Authority, hlc: Hlc) !void {
        const claim = NickClaim{
            .nick = nick,
            .uid = uid,
            .authority = authority,
            .hlc = hlc,
            .node_id = self.node_id,
        };
        try self.insertNickClaim(claim);
    }

    /// Resolve a nick MV-register. Authority deliberately dominates recency;
    /// equal-authority/equal-HLC conflicts use node/UID only as deterministic
    /// winner keys, and losers are mapped to their UID rather than killed.
    pub fn resolveNick(self: *const Self, nick: Nick, uid: Uid) NickResolution {
        const winner = self.winningNickClaim(nick) orelse return .{
            .outcome = .absent,
            .display = nick,
            .winner_uid = null,
        };
        if (Uid.eql(winner.uid, uid)) {
            return .{ .outcome = .keep_nick, .display = nick, .winner_uid = winner.uid };
        }
        if (self.hasNickClaimForUid(nick, uid)) {
            var display = Nick.empty();
            const copy_len = @min(uid.len, display.bytes.len);
            if (copy_len != 0) @memcpy(display.bytes[0..copy_len], uid.bytes[0..copy_len]);
            display.len = @intCast(copy_len);
            return .{ .outcome = .rename_to_uid, .display = display, .winner_uid = winner.uid };
        }
        return .{ .outcome = .absent, .display = nick, .winner_uid = winner.uid };
    }

    pub fn createChannel(self: *Self, name: ChannelName, birth_hlc: Hlc, authority: Authority) !void {
        const idx = self.findChannelIndex(name);
        if (idx) |found| {
            applyChannelBirth(&self.channels.items[found], birth_hlc, authority, self.node_id);
            return;
        }
        try self.channels.append(self.allocator, .{
            .name = name,
            .birth_hlc = birth_hlc,
            .has_birth = true,
            .authority = authority,
            .node_id = self.node_id,
        });
    }

    pub fn channelBirth(self: *const Self, name: ChannelName) ?Hlc {
        const idx = self.findChannelIndex(name) orelse return null;
        const root = self.channels.items[idx];
        if (!root.has_birth) return null;
        return root.birth_hlc;
    }

    pub fn join(self: *Self, channel: ChannelName, uid: Uid, session: u64) !void {
        var delta = try self.memberships.add(.{ .channel = channel, .uid = uid, .session = session });
        delta.deinit();
    }

    pub fn part(self: *Self, channel: ChannelName, uid: Uid, session: u64) !void {
        var delta = try self.memberships.remove(.{ .channel = channel, .uid = uid, .session = session });
        delta.deinit();
    }

    pub fn hasMember(self: *const Self, channel: ChannelName, uid: Uid, session: u64) bool {
        return self.memberships.contains(.{ .channel = channel, .uid = uid, .session = session });
    }

    pub fn setPrefixMode(self: *Self, key: PrefixModeKey, enabled: bool, authority: Authority, hlc: Hlc) !void {
        const toggle = AuthToggle{ .enabled = enabled, .authority = authority, .hlc = hlc, .node_id = self.node_id };
        if (self.findPrefixModeIndex(key)) |idx| {
            self.prefix_modes.items[idx].toggle.merge(toggle);
            return;
        }
        try self.prefix_modes.append(self.allocator, .{ .key = key, .toggle = toggle });
    }

    pub fn setBooleanMode(self: *Self, key: BooleanModeKey, policy: BooleanModePolicy, enabled: bool, hlc: Hlc) !void {
        if (self.findBooleanModeIndex(key)) |idx| {
            self.boolean_modes.items[idx].toggle.set(enabled, hlc, self.node_id);
            return;
        }
        var toggle = CausalToggleRegister.init(policy);
        toggle.set(enabled, hlc, self.node_id);
        try self.boolean_modes.append(self.allocator, .{ .key = key, .toggle = toggle });
    }

    pub fn setParamMode(self: *Self, key: ParamModeKey, value: ModeParam, authority: Authority, hlc: Hlc) !void {
        const update = ParamModeValue{ .value = value, .authority = authority };
        if (self.findParamModeIndex(key)) |idx| {
            mergeParamRegister(&self.param_modes.items[idx].register, update, hlc, self.node_id);
            return;
        }
        var entry = ParamModeEntry{ .key = key };
        mergeParamRegister(&entry.register, update, hlc, self.node_id);
        try self.param_modes.append(self.allocator, entry);
    }

    pub fn addBan(self: *Self, channel: ChannelName, kind: BanKind, mask_text: []const u8, metadata: BanMetadata, hlc: Hlc) !void {
        const key = BanKey{ .channel = channel, .kind = kind, .mask = try Mask.initLower(mask_text) };
        var delta = try self.bans.add(key);
        delta.deinit();
        try self.mergeBanMetadata(key, metadata, hlc);
    }

    pub fn removeBan(self: *Self, channel: ChannelName, kind: BanKind, mask_text: []const u8) !void {
        const key = BanKey{ .channel = channel, .kind = kind, .mask = try Mask.initLower(mask_text) };
        var delta = try self.bans.remove(key);
        delta.deinit();
    }

    pub fn hasBan(self: *const Self, channel: ChannelName, kind: BanKind, mask_text: []const u8) !bool {
        const key = BanKey{ .channel = channel, .kind = kind, .mask = try Mask.initLower(mask_text) };
        return self.bans.contains(key);
    }

    pub fn setTopic(self: *Self, channel: ChannelName, text: TopicText, setter: Uid, hlc: Hlc) !void {
        const value = TopicValue{ .text = text, .setter = setter, .hlc = hlc };
        if (self.findTopicIndex(channel)) |idx| {
            _ = self.topics.items[idx].register.set(value, hlc.toU64(), self.node_id);
            return;
        }
        var entry = TopicEntry{ .channel = channel };
        _ = entry.register.set(value, hlc.toU64(), self.node_id);
        try self.topics.append(self.allocator, entry);
    }

    pub fn merge(self: *Self, other: *const Self) !void {
        for (other.users.items) |other_user| {
            const entry = try self.ensureUser(other_user.uid);
            entry.profile.merge(other_user.profile);
            entry.presence.merge(other_user.presence);
        }

        for (other.nick_claims.items) |claim| try self.insertNickClaim(claim);

        for (other.channels.items) |channel| {
            if (self.findChannelIndex(channel.name)) |idx| {
                mergeChannelRoot(&self.channels.items[idx], channel);
            } else {
                try self.channels.append(self.allocator, channel);
            }
        }

        try self.memberships.merge(other.memberships);
        try self.mergePrefixModes(other);
        try self.mergeBooleanModes(other);
        try self.mergeParamModes(other);
        try self.bans.merge(other.bans);
        try self.mergeBanMetadataEntries(other);
        try self.mergeTopics(other);
    }

    pub fn eql(a: *const Self, b: *const Self) bool {
        return userListsEql(a.users.items, b.users.items) and
            nickClaimListsEql(a.nick_claims.items, b.nick_claims.items) and
            channelListsEql(a.channels.items, b.channels.items) and
            MembershipSet.eql(a.memberships, b.memberships) and
            prefixListsEql(a.prefix_modes.items, b.prefix_modes.items) and
            booleanListsEql(a.boolean_modes.items, b.boolean_modes.items) and
            paramListsEql(a.param_modes.items, b.param_modes.items) and
            BanSet.eql(a.bans, b.bans) and
            banMetadataListsEql(a.ban_metadata.items, b.ban_metadata.items) and
            topicListsEql(a.topics.items, b.topics.items);
    }

    fn ensureUser(self: *Self, uid: Uid) !*UserEntry {
        if (self.findUserIndex(uid)) |idx| return &self.users.items[idx];
        try self.users.append(self.allocator, .{ .uid = uid });
        return &self.users.items[self.users.items.len - 1];
    }

    fn findUserIndex(self: *const Self, uid: Uid) ?usize {
        for (self.users.items, 0..) |entry, idx| {
            if (Uid.eql(entry.uid, uid)) return idx;
        }
        return null;
    }

    fn winningNickClaim(self: *const Self, nick: Nick) ?NickClaim {
        var winner: ?NickClaim = null;
        for (self.nick_claims.items) |claim| {
            if (!Nick.eql(claim.nick, nick)) continue;
            if (winner == null or nickClaimWins(claim, winner.?)) winner = claim;
        }
        return winner;
    }

    fn hasNickClaimForUid(self: *const Self, nick: Nick, uid: Uid) bool {
        for (self.nick_claims.items) |claim| {
            if (Nick.eql(claim.nick, nick) and Uid.eql(claim.uid, uid)) return true;
        }
        return false;
    }

    fn insertNickClaim(self: *Self, claim: NickClaim) !void {
        if (!containsNickClaim(self.nick_claims.items, claim)) {
            try self.nick_claims.append(self.allocator, claim);
        }
        self.pruneNickClaimsForNick(claim.nick);
    }

    fn pruneNickClaimsForNick(self: *Self, nick: Nick) void {
        const winner = self.winningNickClaim(nick) orelse return;
        var write: usize = 0;
        for (self.nick_claims.items) |claim| {
            if (!Nick.eql(claim.nick, nick) or keepNickClaimAfterPrune(self.nick_claims.items, claim, winner)) {
                self.nick_claims.items[write] = claim;
                write += 1;
            }
        }
        self.nick_claims.shrinkRetainingCapacity(write);
    }

    fn findChannelIndex(self: *const Self, name: ChannelName) ?usize {
        for (self.channels.items, 0..) |entry, idx| {
            if (ChannelName.eql(entry.name, name)) return idx;
        }
        return null;
    }

    fn findPrefixModeIndex(self: *const Self, key: PrefixModeKey) ?usize {
        for (self.prefix_modes.items, 0..) |entry, idx| {
            if (std.meta.eql(entry.key, key)) return idx;
        }
        return null;
    }

    fn findBooleanModeIndex(self: *const Self, key: BooleanModeKey) ?usize {
        for (self.boolean_modes.items, 0..) |entry, idx| {
            if (std.meta.eql(entry.key, key)) return idx;
        }
        return null;
    }

    fn findParamModeIndex(self: *const Self, key: ParamModeKey) ?usize {
        for (self.param_modes.items, 0..) |entry, idx| {
            if (std.meta.eql(entry.key, key)) return idx;
        }
        return null;
    }

    fn mergeBanMetadata(self: *Self, key: BanKey, metadata: BanMetadata, hlc: Hlc) !void {
        if (self.findBanMetadataIndex(key)) |idx| {
            _ = self.ban_metadata.items[idx].register.set(metadata, hlc.toU64(), self.node_id);
            return;
        }
        var entry = BanMetadataEntry{ .key = key };
        _ = entry.register.set(metadata, hlc.toU64(), self.node_id);
        try self.ban_metadata.append(self.allocator, entry);
    }

    fn findBanMetadataIndex(self: *const Self, key: BanKey) ?usize {
        for (self.ban_metadata.items, 0..) |entry, idx| {
            if (std.meta.eql(entry.key, key)) return idx;
        }
        return null;
    }

    fn findTopicIndex(self: *const Self, channel: ChannelName) ?usize {
        for (self.topics.items, 0..) |entry, idx| {
            if (ChannelName.eql(entry.channel, channel)) return idx;
        }
        return null;
    }

    fn mergePrefixModes(self: *Self, other: *const Self) !void {
        for (other.prefix_modes.items) |entry| {
            if (self.findPrefixModeIndex(entry.key)) |idx| {
                self.prefix_modes.items[idx].toggle.merge(entry.toggle);
            } else {
                try self.prefix_modes.append(self.allocator, entry);
            }
        }
    }

    fn mergeBooleanModes(self: *Self, other: *const Self) !void {
        for (other.boolean_modes.items) |entry| {
            if (self.findBooleanModeIndex(entry.key)) |idx| {
                self.boolean_modes.items[idx].toggle.merge(entry.toggle);
            } else {
                try self.boolean_modes.append(self.allocator, entry);
            }
        }
    }

    fn mergeParamModes(self: *Self, other: *const Self) !void {
        for (other.param_modes.items) |entry| {
            if (self.findParamModeIndex(entry.key)) |idx| {
                mergeParamRegisters(&self.param_modes.items[idx].register, entry.register);
            } else {
                try self.param_modes.append(self.allocator, entry);
            }
        }
    }

    fn mergeBanMetadataEntries(self: *Self, other: *const Self) !void {
        for (other.ban_metadata.items) |entry| {
            if (self.findBanMetadataIndex(entry.key)) |idx| {
                self.ban_metadata.items[idx].register.merge(entry.register);
            } else {
                try self.ban_metadata.append(self.allocator, entry);
            }
        }
    }

    fn mergeTopics(self: *Self, other: *const Self) !void {
        for (other.topics.items) |entry| {
            if (self.findTopicIndex(entry.channel)) |idx| {
                self.topics.items[idx].register.merge(entry.register);
            } else {
                try self.topics.append(self.allocator, entry);
            }
        }
    }
};

fn nickClaimWins(candidate: NickClaim, current: NickClaim) bool {
    if (candidate.authority != current.authority) return candidate.authority > current.authority;
    switch (Hlc.compare(candidate.hlc, current.hlc)) {
        .gt => return true,
        .lt => return false,
        .eq => {},
    }
    if (candidate.node_id != current.node_id) return candidate.node_id > current.node_id;
    return Uid.lessThan(candidate.uid, current.uid);
}

fn keepNickClaimAfterPrune(items: []const NickClaim, claim: NickClaim, winner: NickClaim) bool {
    if (std.meta.eql(claim, winner)) return true;
    if (Uid.eql(claim.uid, winner.uid)) return false;
    for (items) |other| {
        if (!Nick.eql(other.nick, claim.nick)) continue;
        if (!Uid.eql(other.uid, claim.uid)) continue;
        if (std.meta.eql(other, claim)) continue;
        if (nickClaimWins(other, claim)) return false;
    }
    return true;
}

fn authToggleWins(candidate: AuthToggle, current: AuthToggle) bool {
    if (candidate.authority != current.authority) return candidate.authority > current.authority;
    switch (Hlc.compare(candidate.hlc, current.hlc)) {
        .gt => return true,
        .lt => return false,
        .eq => {},
    }
    if (candidate.enabled != current.enabled) return candidate.enabled;
    return candidate.node_id > current.node_id;
}

fn toggleWins(candidate: CausalToggleRegister, current: CausalToggleRegister) bool {
    switch (Hlc.compare(candidate.hlc, current.hlc)) {
        .gt => return true,
        .lt => return false,
        .eq => {},
    }
    if (candidate.enabled != current.enabled) {
        return candidate.policy == .add_wins;
    }
    return candidate.node_id > current.node_id;
}

fn paramWins(candidate: ParamModeValue, candidate_ts: u64, candidate_node: NodeId, current: LwwRegister(ParamModeValue)) bool {
    if (current.value == null) return true;
    const current_value = current.value.?;
    if (candidate.authority != current_value.authority) return candidate.authority > current_value.authority;
    if (candidate_ts != current.timestamp) return candidate_ts > current.timestamp;
    if (candidate_node != current.replica_id) return candidate_node > current.replica_id;
    return std.mem.order(u8, std.mem.asBytes(&candidate), std.mem.asBytes(&current_value)) == .gt;
}

fn mergeParamRegister(register: *LwwRegister(ParamModeValue), value: ParamModeValue, hlc: Hlc, node_id: NodeId) void {
    const ts = hlc.toU64();
    if (paramWins(value, ts, node_id, register.*)) {
        register.* = .{ .value = value, .timestamp = ts, .replica_id = node_id };
    }
}

fn mergeParamRegisters(register: *LwwRegister(ParamModeValue), other: LwwRegister(ParamModeValue)) void {
    const value = other.value orelse return;
    if (paramWins(value, other.timestamp, other.replica_id, register.*)) {
        register.* = other;
    }
}

fn applyChannelBirth(root: *ChannelRoot, birth_hlc: Hlc, authority: Authority, node_id: NodeId) void {
    if (channelBirthWins(.{
        .name = root.name,
        .birth_hlc = birth_hlc,
        .has_birth = true,
        .authority = authority,
        .node_id = node_id,
    }, root.*)) {
        root.birth_hlc = birth_hlc;
        root.has_birth = true;
        root.authority = authority;
        root.node_id = node_id;
    }
}

fn mergeChannelRoot(target: *ChannelRoot, other: ChannelRoot) void {
    if (!other.has_birth) return;
    applyChannelBirth(target, other.birth_hlc, other.authority, other.node_id);
}

fn channelBirthWins(candidate: ChannelRoot, current: ChannelRoot) bool {
    if (!candidate.has_birth) return false;
    if (!current.has_birth) return true;
    switch (Hlc.compare(candidate.birth_hlc, current.birth_hlc)) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    }
    if (candidate.authority != current.authority) return candidate.authority > current.authority;
    return candidate.node_id > current.node_id;
}

fn containsNickClaim(items: []const NickClaim, claim: NickClaim) bool {
    for (items) |item| {
        if (std.meta.eql(item, claim)) return true;
    }
    return false;
}

fn userListsEql(a: []const UserEntry, b: []const UserEntry) bool {
    if (a.len != b.len) return false;
    for (a) |item| {
        var found = false;
        for (b) |other| {
            if (Uid.eql(item.uid, other.uid)) {
                if (!LwwRegister(UserProfile).eql(item.profile, other.profile)) return false;
                if (!LwwRegister(PresenceLease).eql(item.presence, other.presence)) return false;
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn nickClaimListsEql(a: []const NickClaim, b: []const NickClaim) bool {
    if (a.len != b.len) return false;
    for (a) |item| {
        if (!containsNickClaim(b, item)) return false;
    }
    return true;
}

fn channelListsEql(a: []const ChannelRoot, b: []const ChannelRoot) bool {
    if (a.len != b.len) return false;
    for (a) |item| {
        var found = false;
        for (b) |other| {
            if (std.meta.eql(item, other)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn prefixListsEql(a: []const PrefixModeEntry, b: []const PrefixModeEntry) bool {
    if (a.len != b.len) return false;
    for (a) |item| {
        var found = false;
        for (b) |other| {
            if (std.meta.eql(item, other)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn booleanListsEql(a: []const BooleanModeEntry, b: []const BooleanModeEntry) bool {
    if (a.len != b.len) return false;
    for (a) |item| {
        var found = false;
        for (b) |other| {
            if (std.meta.eql(item, other)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn paramListsEql(a: []const ParamModeEntry, b: []const ParamModeEntry) bool {
    if (a.len != b.len) return false;
    for (a) |item| {
        var found = false;
        for (b) |other| {
            if (std.meta.eql(item, other)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn banMetadataListsEql(a: []const BanMetadataEntry, b: []const BanMetadataEntry) bool {
    if (a.len != b.len) return false;
    for (a) |item| {
        var found = false;
        for (b) |other| {
            if (std.meta.eql(item, other)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn topicListsEql(a: []const TopicEntry, b: []const TopicEntry) bool {
    if (a.len != b.len) return false;
    for (a) |item| {
        var found = false;
        for (b) |other| {
            if (std.meta.eql(item, other)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn makeHlc(wall_ms: u64, logical: u16) !Hlc {
    return Hlc.init(wall_ms, logical);
}

test "network state converges when replicas apply operations in different orders" {
    const allocator = std.testing.allocator;
    const chan = try ChannelName.init("#mizuchi");
    const uid_a = try Uid.init("001AAAAAA");
    const uid_b = try Uid.init("002BBBBBB");
    const nick_a = try Nick.init("alice");
    const nick_b = try Nick.init("bob");

    var left = NetworkState.init(allocator, 1, 10);
    defer left.deinit();
    var right = NetworkState.init(allocator, 2, 20);
    defer right.deinit();

    try left.upsertUser(uid_a, .{ .nick = nick_a, .realname = try ShortText.init("Alice") }, try makeHlc(1000, 0), 10);
    try left.claimNick(nick_a, uid_a, 10, try makeHlc(1001, 0));
    try left.createChannel(chan, try makeHlc(900, 0), 10);
    try left.join(chan, uid_a, 1);
    try left.setPrefixMode(.{ .channel = chan, .uid = uid_a, .mode = 'o' }, true, 10, try makeHlc(1002, 0));
    try left.setBooleanMode(.{ .channel = chan, .mode = 'm' }, .add_wins, true, try makeHlc(1003, 0));
    try left.setParamMode(.{ .channel = chan, .mode = 'l' }, try ModeParam.init("50"), 10, try makeHlc(1004, 0));
    try left.setTopic(chan, try TopicText.init("mesh state"), uid_a, try makeHlc(1005, 0));

    try right.setTopic(chan, try TopicText.init("older topic"), uid_b, try makeHlc(950, 0));
    try right.upsertUser(uid_b, .{ .nick = nick_b, .realname = try ShortText.init("Bob") }, try makeHlc(1000, 1), 10);
    try right.claimNick(nick_b, uid_b, 10, try makeHlc(1001, 1));
    try right.createChannel(chan, try makeHlc(901, 0), 10);
    try right.join(chan, uid_b, 1);
    try right.addBan(chan, .ban, "*!*@EXAMPLE.test", .{ .setter = uid_b, .reason = try ShortText.init("test") }, try makeHlc(1006, 0));

    try left.merge(&right);
    try right.merge(&left);

    try std.testing.expect(NetworkState.eql(&left, &right));
    try std.testing.expect(left.hasMember(chan, uid_a, 1));
    try std.testing.expect(left.hasMember(chan, uid_b, 1));
    try std.testing.expect(try left.hasBan(chan, .ban, "*!*@example.test"));
}

test "nick collision resolves by rename to UID instead of kill" {
    const allocator = std.testing.allocator;
    const nick = try Nick.init("same");
    const uid_winner = try Uid.init("001WINNER");
    const uid_loser = try Uid.init("002LOSER");

    var state = NetworkState.init(allocator, 1, 100);
    defer state.deinit();

    try state.claimNick(nick, uid_loser, 10, try makeHlc(2000, 0));
    state.node_id = 200;
    try state.claimNick(nick, uid_winner, 20, try makeHlc(1999, 0));

    const loser = state.resolveNick(nick, uid_loser);
    try std.testing.expectEqual(NickOutcome.rename_to_uid, loser.outcome);
    try std.testing.expect(std.mem.eql(u8, uid_loser.asSlice(), loser.display.asSlice()));
    try std.testing.expectEqual(uid_winner, loser.winner_uid.?);

    const winner = state.resolveNick(nick, uid_winner);
    try std.testing.expectEqual(NickOutcome.keep_nick, winner.outcome);
}

test "channel birth timestamp converges to minimum HLC" {
    const allocator = std.testing.allocator;
    const chan = try ChannelName.init("#ts");

    var a = NetworkState.init(allocator, 1, 10);
    defer a.deinit();
    var b = NetworkState.init(allocator, 2, 20);
    defer b.deinit();

    const older = try makeHlc(1000, 0);
    const newer = try makeHlc(1001, 0);

    try a.createChannel(chan, newer, 10);
    try b.createChannel(chan, older, 10);
    try a.merge(&b);
    try b.merge(&a);

    try std.testing.expectEqual(older, a.channelBirth(chan).?);
    try std.testing.expectEqual(older, b.channelBirth(chan).?);
    try std.testing.expect(NetworkState.eql(&a, &b));
}

test "channel birth HLC tie converges by authority and node id" {
    const allocator = std.testing.allocator;
    const chan = try ChannelName.init("#tie");
    const birth = try makeHlc(1000, 7);

    var a = NetworkState.init(allocator, 1, 10);
    defer a.deinit();
    var b = NetworkState.init(allocator, 2, 20);
    defer b.deinit();

    try a.createChannel(chan, birth, 10);
    try b.createChannel(chan, birth, 20);
    try a.merge(&b);
    try b.merge(&a);

    try std.testing.expect(NetworkState.eql(&a, &b));
    try std.testing.expectEqual(@as(Authority, 20), a.channels.items[0].authority);
    try std.testing.expectEqual(@as(NodeId, 20), a.channels.items[0].node_id);
    try std.testing.expectEqual(a.channels.items[0], b.channels.items[0]);
}

test "param mode equal writer conflicts converge by value bytes" {
    const allocator = std.testing.allocator;
    const chan = try ChannelName.init("#params");
    const key = ParamModeKey{ .channel = chan, .mode = 'k' };
    const hlc = try makeHlc(3000, 1);

    var a = NetworkState.init(allocator, 1, 77);
    defer a.deinit();
    var b = NetworkState.init(allocator, 2, 77);
    defer b.deinit();

    try a.setParamMode(key, try ModeParam.init("alpha"), 10, hlc);
    try b.setParamMode(key, try ModeParam.init("omega"), 10, hlc);
    try a.merge(&b);
    try b.merge(&a);

    try std.testing.expect(NetworkState.eql(&a, &b));
    const value = a.param_modes.items[0].register.value.?;
    try std.testing.expect(std.mem.eql(u8, "omega", value.value.asSlice()));
}

test "ban add and remove use observed-remove semantics" {
    const allocator = std.testing.allocator;
    const chan = try ChannelName.init("#mask");
    const setter = try Uid.init("001SETTER");

    var a = NetworkState.init(allocator, 1, 10);
    defer a.deinit();
    var b = NetworkState.init(allocator, 2, 20);
    defer b.deinit();

    try a.addBan(chan, .ban, "*!*@Example.test", .{ .setter = setter }, try makeHlc(1000, 0));
    try b.merge(&a);
    try b.removeBan(chan, .ban, "*!*@example.test");
    try a.addBan(chan, .ban, "*!*@example.test", .{ .setter = setter }, try makeHlc(1001, 0));

    try a.merge(&b);
    try b.merge(&a);

    try std.testing.expect(try a.hasBan(chan, .ban, "*!*@example.test"));
    try std.testing.expect(try b.hasBan(chan, .ban, "*!*@EXAMPLE.test"));
    try std.testing.expect(NetworkState.eql(&a, &b));
}
