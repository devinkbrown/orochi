// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure CRDT model for one IRC channel.
//!
//! Membership is an add-wins observed-remove set keyed by stable member id.
//! Channel modes are LWW registers ordered by `(HLC, replica_id)`.
const std = @import("std");

const clock = @import("clock.zig");
const delta_codec = @import("delta_codec.zig");
const goryu = @import("goryu.zig");

pub const Hlc = clock.Hlc;
pub const VersionVector = clock.VersionVector;
pub const WireFamily = delta_codec.EntityFamily.channel_modes;

pub const ReplicaId = u64;
pub const MemberId = u64;

pub const Dot = struct {
    replica_id: ReplicaId,
    counter: u64,
};

pub const MemberStatus = packed struct(u8) {
    voice: bool = false,
    op: bool = false,
    owner: bool = false,
    founder: bool = false,
    reserved: u4 = 0,

    pub fn init(bits_value: u4) MemberStatus {
        return @bitCast(@as(u8, bits_value));
    }

    pub fn bits(self: MemberStatus) u4 {
        return @intCast(@as(u8, @bitCast(self)) & 0x0f);
    }

    fn unionWith(a: MemberStatus, b: MemberStatus) MemberStatus {
        return MemberStatus.init(a.bits() | b.bits());
    }
};

pub const KeyMode = struct {
    pub const max_len = 64;
    pub const Error = error{KeyTooLong};

    present: bool = false,
    bytes: [max_len]u8 = [_]u8{0} ** max_len,
    len: u8 = 0,

    pub fn init(key: []const u8) Error!KeyMode {
        if (key.len > max_len) return error.KeyTooLong;
        var out = KeyMode{ .present = true, .len = @intCast(key.len) };
        if (key.len != 0) @memcpy(out.bytes[0..key.len], key);
        return out;
    }

    pub fn none() KeyMode {
        return .{};
    }

    pub fn asSlice(self: *const KeyMode) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const LimitMode = struct {
    present: bool = false,
    value: u32 = 0,

    pub fn set(value: u32) LimitMode {
        return .{ .present = true, .value = value };
    }

    pub fn none() LimitMode {
        return .{};
    }
};

pub const ModeUpdate = union(enum) {
    invite_only: bool,
    moderated: bool,
    no_external: bool,
    topic_protected: bool,
    secret: bool,
    key: KeyMode,
    limit: LimitMode,
};

const BoolRegister = goryu.LwwRegister(bool);
const KeyRegister = goryu.LwwRegister(KeyMode);
const LimitRegister = goryu.LwwRegister(LimitMode);

pub const ChannelModes = struct {
    invite_only: BoolRegister = BoolRegister.init(),
    moderated: BoolRegister = BoolRegister.init(),
    no_external: BoolRegister = BoolRegister.init(),
    topic_protected: BoolRegister = BoolRegister.init(),
    secret: BoolRegister = BoolRegister.init(),
    key: KeyRegister = KeyRegister.init(),
    limit: LimitRegister = LimitRegister.init(),

    pub fn merge(self: *ChannelModes, other: ChannelModes) void {
        self.invite_only.merge(other.invite_only);
        self.moderated.merge(other.moderated);
        self.no_external.merge(other.no_external);
        self.topic_protected.merge(other.topic_protected);
        self.secret.merge(other.secret);
        self.key.merge(other.key);
        self.limit.merge(other.limit);
    }

    pub fn eql(a: ChannelModes, b: ChannelModes) bool {
        return BoolRegister.eql(a.invite_only, b.invite_only) and
            BoolRegister.eql(a.moderated, b.moderated) and
            BoolRegister.eql(a.no_external, b.no_external) and
            BoolRegister.eql(a.topic_protected, b.topic_protected) and
            BoolRegister.eql(a.secret, b.secret) and
            KeyRegister.eql(a.key, b.key) and
            LimitRegister.eql(a.limit, b.limit);
    }

    fn set(self: *ChannelModes, update: ModeUpdate, hlc: Hlc, replica_id: ReplicaId) void {
        const timestamp = hlc.toU64();
        const rid: u64 = replica_id;
        switch (update) {
            .invite_only => |value| _ = self.invite_only.set(value, timestamp, rid),
            .moderated => |value| _ = self.moderated.set(value, timestamp, rid),
            .no_external => |value| _ = self.no_external.set(value, timestamp, rid),
            .topic_protected => |value| _ = self.topic_protected.set(value, timestamp, rid),
            .secret => |value| _ = self.secret.set(value, timestamp, rid),
            .key => |value| _ = self.key.set(value, timestamp, rid),
            .limit => |value| _ = self.limit.set(value, timestamp, rid),
        }
    }
};

const MemberAdd = struct {
    dot: Dot,
    hlc: Hlc,
    status: MemberStatus,
};

const MemberEntry = struct {
    member_id: MemberId,
    adds: std.ArrayList(MemberAdd) = .empty,
    context: VersionVector = VersionVector.init(),

    fn deinit(self: *MemberEntry, allocator: std.mem.Allocator) void {
        self.adds.deinit(allocator);
    }
};

pub const ChannelCrdt = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    replica_id: ReplicaId,
    hlc: Hlc = .{},
    vv: VersionVector = VersionVector.init(),
    members: std.ArrayList(MemberEntry) = .empty,
    modes: ChannelModes = .{},

    pub fn init(allocator: std.mem.Allocator, replica_id: ReplicaId) Self {
        return .{
            .allocator = allocator,
            .replica_id = replica_id,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.members.items) |*entry| entry.deinit(self.allocator);
        self.members.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn localJoin(self: *Self, member_id: MemberId, status: MemberStatus, physical_ms: u64) !Self {
        const dot = try self.nextDot();
        const timestamp = try self.hlc.now(physical_ms);

        var delta = Self.init(self.allocator, self.replica_id);
        errdefer delta.deinit();
        delta.hlc = timestamp;
        delta.vv = self.vv;

        const entry = try self.ensureMember(member_id);
        const delta_entry = try delta.ensureMember(member_id);
        delta_entry.context = entry.context;
        try observeDot(&entry.context, dot);
        try observeDot(&delta_entry.context, dot);

        removeAddsCoveredByDots(entry, delta_entry.context, &.{dot});

        const add = MemberAdd{ .dot = dot, .hlc = timestamp, .status = status };
        try entry.adds.append(self.allocator, add);
        try delta_entry.adds.append(delta.allocator, add);
        return delta;
    }

    pub fn localPart(self: *Self, member_id: MemberId) !Self {
        var delta = Self.init(self.allocator, self.replica_id);
        errdefer delta.deinit();
        delta.hlc = self.hlc;
        delta.vv = self.vv;

        const idx = self.findMemberIndex(member_id) orelse return delta;
        const entry = &self.members.items[idx];
        const delta_entry = try delta.ensureMember(member_id);
        delta_entry.context = entry.context;
        entry.adds.clearRetainingCapacity();
        return delta;
    }

    pub fn localSetMode(self: *Self, update: ModeUpdate, physical_ms: u64) !Self {
        const timestamp = try self.hlc.now(physical_ms);
        self.modes.set(update, timestamp, self.replica_id);

        var delta = Self.init(self.allocator, self.replica_id);
        errdefer delta.deinit();
        delta.hlc = timestamp;
        delta.vv = self.vv;
        delta.modes.set(update, timestamp, self.replica_id);
        return delta;
    }

    pub fn merge(self: *Self, other: *const Self) !void {
        if (Hlc.compare(other.hlc, self.hlc) == .gt) self.hlc = other.hlc;
        try self.vv.merge(&other.vv);

        for (other.members.items) |other_entry| {
            const entry = try self.ensureMember(other_entry.member_id);

            removeAddsCoveredByAdds(entry, other_entry.context, other_entry.adds.items);
            for (other_entry.adds.items) |add| {
                if (!entry.context.contains(toClockDot(add.dot)) and !containsAdd(entry.adds.items, add.dot)) {
                    try entry.adds.append(self.allocator, add);
                }
            }
            try entry.context.merge(&other_entry.context);
        }

        self.modes.merge(other.modes);
    }

    pub fn clone(self: *const Self) !Self {
        var out = Self.init(self.allocator, self.replica_id);
        errdefer out.deinit();
        out.hlc = self.hlc;
        out.vv = self.vv;
        out.modes = self.modes;

        for (self.members.items) |entry| {
            var adds = std.ArrayList(MemberAdd).empty;
            errdefer adds.deinit(out.allocator);
            try adds.appendSlice(out.allocator, entry.adds.items);
            try out.members.append(out.allocator, .{
                .member_id = entry.member_id,
                .adds = adds,
                .context = entry.context,
            });
        }
        return out;
    }

    pub fn containsMember(self: *const Self, member_id: MemberId) bool {
        const idx = self.findMemberIndex(member_id) orelse return false;
        return self.members.items[idx].adds.items.len != 0;
    }

    pub fn memberStatus(self: *const Self, member_id: MemberId) ?MemberStatus {
        const idx = self.findMemberIndex(member_id) orelse return null;
        var status = MemberStatus{};
        var found = false;
        for (self.members.items[idx].adds.items) |add| {
            status = MemberStatus.unionWith(status, add.status);
            found = true;
        }
        return if (found) status else null;
    }

    pub fn eql(a: *const Self, b: *const Self) bool {
        return Hlc.compare(a.hlc, b.hlc) == .eq and
            vvEql(a.vv, b.vv) and
            memberListsEql(a.members.items, b.members.items) and
            ChannelModes.eql(a.modes, b.modes);
    }

    fn nextDot(self: *Self) !Dot {
        const dot = try self.vv.increment(self.replica_id);
        return fromClockDot(dot);
    }

    fn ensureMember(self: *Self, member_id: MemberId) !*MemberEntry {
        if (self.findMemberIndex(member_id)) |idx| return &self.members.items[idx];
        try self.members.append(self.allocator, .{ .member_id = member_id });
        return &self.members.items[self.members.items.len - 1];
    }

    fn findMemberIndex(self: *const Self, member_id: MemberId) ?usize {
        for (self.members.items, 0..) |entry, idx| {
            if (entry.member_id == member_id) return idx;
        }
        return null;
    }
};

fn fromClockDot(dot: clock.Dot) !Dot {
    if (dot.replica > std.math.maxInt(ReplicaId)) return error.ReplicaIdOutOfRange;
    return .{ .replica_id = @intCast(dot.replica), .counter = dot.counter };
}

fn toClockDot(dot: Dot) clock.Dot {
    return .{ .replica = dot.replica_id, .counter = dot.counter };
}

fn observeDot(vv: *VersionVector, dot: Dot) !void {
    var single = VersionVector.init();
    single.entries[0] = .{ .replica = dot.replica_id, .counter = dot.counter };
    single.len = 1;
    try vv.merge(&single);
}

fn removeAddsCoveredByDots(entry: *MemberEntry, context: VersionVector, keep: []const Dot) void {
    var idx: usize = 0;
    while (idx < entry.adds.items.len) {
        const add = entry.adds.items[idx];
        if (context.contains(toClockDot(add.dot)) and !containsDot(keep, add.dot)) {
            _ = entry.adds.swapRemove(idx);
        } else {
            idx += 1;
        }
    }
}

fn removeAddsCoveredByAdds(entry: *MemberEntry, context: VersionVector, keep: []const MemberAdd) void {
    var idx: usize = 0;
    while (idx < entry.adds.items.len) {
        const add = entry.adds.items[idx];
        if (context.contains(toClockDot(add.dot)) and !containsLiveDot(keep, add.dot)) {
            _ = entry.adds.swapRemove(idx);
        } else {
            idx += 1;
        }
    }
}

fn containsDot(dots: []const Dot, dot: Dot) bool {
    for (dots) |candidate| {
        if (dotEql(candidate, dot)) return true;
    }
    return false;
}

fn containsLiveDot(adds: []const MemberAdd, dot: Dot) bool {
    for (adds) |add| {
        if (dotEql(add.dot, dot)) return true;
    }
    return false;
}

fn containsAdd(adds: []const MemberAdd, dot: Dot) bool {
    return containsLiveDot(adds, dot);
}

fn dotEql(a: Dot, b: Dot) bool {
    return a.replica_id == b.replica_id and a.counter == b.counter;
}

fn memberListsEql(a: []const MemberEntry, b: []const MemberEntry) bool {
    if (a.len != b.len) return false;
    for (a) |entry_a| {
        const entry_b = findEntry(b, entry_a.member_id) orelse return false;
        if (!vvEql(entry_a.context, entry_b.context)) return false;
        if (!addListsEql(entry_a.adds.items, entry_b.adds.items)) return false;
    }
    return true;
}

fn findEntry(entries: []const MemberEntry, member_id: MemberId) ?MemberEntry {
    for (entries) |entry| {
        if (entry.member_id == member_id) return entry;
    }
    return null;
}

fn addListsEql(a: []const MemberAdd, b: []const MemberAdd) bool {
    if (a.len != b.len) return false;
    for (a) |add_a| {
        var found = false;
        for (b) |add_b| {
            if (dotEql(add_a.dot, add_b.dot) and
                Hlc.compare(add_a.hlc, add_b.hlc) == .eq and
                std.meta.eql(add_a.status, add_b.status))
            {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn vvEql(a: VersionVector, b: VersionVector) bool {
    if (a.len != b.len) return false;
    for (a.entries[0..a.len]) |entry| {
        if (b.counter(entry.replica) != entry.counter) return false;
    }
    return true;
}

fn applyRandomOp(state: *ChannelCrdt, random: std.Random, step: u64) !void {
    const member = @as(MemberId, 1000 + random.intRangeLessThan(u16, 0, 12));
    const physical = 10_000 + step;
    switch (random.intRangeLessThan(u8, 0, 9)) {
        0, 1, 2, 3 => {
            var delta = try state.localJoin(member, MemberStatus.init(@intCast(1 + random.intRangeLessThan(u4, 0, 8))), physical);
            delta.deinit();
        },
        4, 5 => {
            var delta = try state.localPart(member);
            delta.deinit();
        },
        6 => {
            var delta = try state.localSetMode(.{ .invite_only = random.boolean() }, physical);
            delta.deinit();
        },
        7 => {
            const value = if (random.boolean()) LimitMode.set(10 + random.intRangeLessThan(u32, 0, 50)) else LimitMode.none();
            var delta = try state.localSetMode(.{ .limit = value }, physical);
            delta.deinit();
        },
        8 => {
            const value = if (random.boolean()) try KeyMode.init("split-key") else KeyMode.none();
            var delta = try state.localSetMode(.{ .key = value }, physical);
            delta.deinit();
        },
        else => unreachable,
    }
}

test "merge commutativity and idempotence on deterministic random ops" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x7c_7d_ca_fe);
    const random = prng.random();

    var a = ChannelCrdt.init(allocator, 1);
    defer a.deinit();
    var b = ChannelCrdt.init(allocator, 2);
    defer b.deinit();

    var step: u64 = 0;
    while (step < 96) : (step += 1) {
        if (random.boolean()) {
            try applyRandomOp(&a, random, step);
        } else {
            try applyRandomOp(&b, random, step);
        }
    }

    var left = try a.clone();
    defer left.deinit();
    try left.merge(&b);

    var right = try b.clone();
    defer right.deinit();
    try right.merge(&a);

    try std.testing.expect(ChannelCrdt.eql(&left, &right));

    var idem = try left.clone();
    defer idem.deinit();
    try idem.merge(&left);
    try std.testing.expect(ChannelCrdt.eql(&idem, &left));
}

test "three replicas converge after disjoint op sets and all merge orders" {
    const allocator = std.testing.allocator;

    var a = ChannelCrdt.init(allocator, 1);
    defer a.deinit();
    var b = ChannelCrdt.init(allocator, 2);
    defer b.deinit();
    var c = ChannelCrdt.init(allocator, 3);
    defer c.deinit();

    var da1 = try a.localJoin(1, .{ .op = true }, 1);
    defer da1.deinit();
    var da2 = try a.localSetMode(.{ .topic_protected = true }, 2);
    defer da2.deinit();

    var db1 = try b.localJoin(2, .{ .voice = true }, 3);
    defer db1.deinit();
    var db2 = try b.localSetMode(.{ .key = try KeyMode.init("mesh") }, 4);
    defer db2.deinit();

    var dc1 = try c.localJoin(3, .{ .owner = true }, 5);
    defer dc1.deinit();
    var dc2 = try c.localSetMode(.{ .limit = LimitMode.set(42) }, 6);
    defer dc2.deinit();

    var abc = try a.clone();
    defer abc.deinit();
    try abc.merge(&b);
    try abc.merge(&c);

    var bca = try b.clone();
    defer bca.deinit();
    try bca.merge(&c);
    try bca.merge(&a);

    var cab = try c.clone();
    defer cab.deinit();
    try cab.merge(&a);
    try cab.merge(&b);

    try std.testing.expect(ChannelCrdt.eql(&abc, &bca));
    try std.testing.expect(ChannelCrdt.eql(&abc, &cab));
}

test "add wins when observed part races with rejoin" {
    const allocator = std.testing.allocator;

    var a = ChannelCrdt.init(allocator, 1);
    defer a.deinit();
    var b = ChannelCrdt.init(allocator, 2);
    defer b.deinit();

    var initial = try a.localJoin(42, .{ .voice = true }, 100);
    defer initial.deinit();
    try b.merge(&initial);

    var part = try b.localPart(42);
    defer part.deinit();
    var rejoin = try a.localJoin(42, .{ .op = true }, 101);
    defer rejoin.deinit();

    var left = try a.clone();
    defer left.deinit();
    try left.merge(&part);

    var right = try b.clone();
    defer right.deinit();
    try right.merge(&rejoin);

    try std.testing.expect(left.containsMember(42));
    try std.testing.expect(right.containsMember(42));
    try std.testing.expectEqual(@as(u4, 0b0010), left.memberStatus(42).?.bits());

    try left.merge(&right);
    try right.merge(&left);
    try std.testing.expect(ChannelCrdt.eql(&left, &right));
    try std.testing.expect(right.containsMember(42));
}

test "netsplit and heal converge channel membership and modes" {
    const allocator = std.testing.allocator;

    var a = ChannelCrdt.init(allocator, 1);
    defer a.deinit();
    var b = ChannelCrdt.init(allocator, 2);
    defer b.deinit();
    var c = ChannelCrdt.init(allocator, 3);
    defer c.deinit();

    var seed_join = try a.localJoin(7, .{ .voice = true }, 1);
    defer seed_join.deinit();
    try b.merge(&seed_join);
    try c.merge(&seed_join);

    var a_rejoin = try a.localJoin(7, .{ .op = true }, 10);
    defer a_rejoin.deinit();
    var a_secret = try a.localSetMode(.{ .secret = true }, 11);
    defer a_secret.deinit();
    var a_key = try a.localSetMode(.{ .key = try KeyMode.init("alpha") }, 12);
    defer a_key.deinit();

    var b_part = try b.localPart(7);
    defer b_part.deinit();
    var b_join = try b.localJoin(8, .{ .voice = true }, 13);
    defer b_join.deinit();

    var c_limit = try c.localSetMode(.{ .limit = LimitMode.set(128) }, 14);
    defer c_limit.deinit();
    var c_invite = try c.localSetMode(.{ .invite_only = true }, 15);
    defer c_invite.deinit();

    var x = try a.clone();
    defer x.deinit();
    try x.merge(&b);
    try x.merge(&c);

    var y = try b.clone();
    defer y.deinit();
    try y.merge(&c);
    try y.merge(&a);

    var z = try c.clone();
    defer z.deinit();
    try z.merge(&a);
    try z.merge(&b);

    try std.testing.expect(ChannelCrdt.eql(&x, &y));
    try std.testing.expect(ChannelCrdt.eql(&x, &z));
    try std.testing.expect(x.containsMember(7));
    try std.testing.expect(x.containsMember(8));
    try std.testing.expectEqual(true, x.modes.secret.get().?);
    try std.testing.expectEqual(true, x.modes.invite_only.get().?);
    try std.testing.expectEqual(@as(u32, 128), x.modes.limit.get().?.value);
    try std.testing.expect(std.mem.eql(u8, "alpha", x.modes.key.get().?.asSlice()));
}
