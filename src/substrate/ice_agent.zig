//! ICE-lite candidate and connectivity-check model for media paths.
//!
//! This module is deliberately transport-free: callers inject STUN I/O and use
//! the checklist as the deterministic state machine around observed binding
//! requests, successes, failures, and remote nomination.

const std = @import("std");
const testing = std.testing;

pub const CandidateKind = enum {
    host,
    srflx,
    prflx,
    relay,
};

pub const Transport = enum {
    udp,
    tcp,
};

pub const AddressFamily = enum {
    ipv4,
    ipv6,
};

pub const Foundation = u32;

pub const Candidate = struct {
    kind: CandidateKind,
    transport: Transport,
    ip: [16]u8,
    family: AddressFamily,
    port: u16,
    priority: u32,
    foundation: Foundation,

    pub fn init(
        kind: CandidateKind,
        transport: Transport,
        family: AddressFamily,
        ip: [16]u8,
        port: u16,
        foundation: Foundation,
        local_pref: u16,
        component: u8,
    ) Candidate {
        return .{
            .kind = kind,
            .transport = transport,
            .ip = ip,
            .family = family,
            .port = port,
            .priority = computePriority(kind, local_pref, component),
            .foundation = foundation,
        };
    }
};

pub const PairState = enum {
    frozen,
    waiting,
    in_progress,
    succeeded,
    failed,
};

pub const CandidatePair = struct {
    local_index: usize,
    remote_index: usize,
    priority: u64,
    state: PairState = .frozen,
    nominated: bool = false,
};

pub const CheckListError = error{
    PairNotFound,
    FailedPair,
};

pub fn typePreference(kind: CandidateKind) u8 {
    return switch (kind) {
        .host => 126,
        .prflx => 110,
        .srflx => 100,
        .relay => 0,
    };
}

/// RFC 8445 candidate priority:
/// `(2^24 * type preference) + (2^8 * local preference) + (256 - component)`.
pub fn computePriority(kind: CandidateKind, local_pref: u16, component: u8) u32 {
    std.debug.assert(component > 0);
    const type_pref: u32 = typePreference(kind);
    return (type_pref << 24) + (@as(u32, local_pref) << 8) + (256 - @as(u32, component));
}

/// RFC 8445 pair priority, using local and remote candidate priorities.
pub fn computePairPriority(local_priority: u32, remote_priority: u32) u64 {
    const local: u64 = local_priority;
    const remote: u64 = remote_priority;
    const low = @min(local, remote);
    const high = @max(local, remote);
    const tie: u64 = if (local > remote) 1 else 0;
    return (@as(u64, 1) << 32) * low + 2 * high + tie;
}

pub const CheckList = struct {
    locals: std.ArrayList(Candidate) = .empty,
    remotes: std.ArrayList(Candidate) = .empty,
    pairs: std.ArrayList(CandidatePair) = .empty,
    selected_pair: ?usize = null,

    const Self = @This();

    pub fn init() Self {
        return .{};
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.locals.deinit(allocator);
        self.remotes.deinit(allocator);
        self.pairs.deinit(allocator);
        self.* = undefined;
    }

    pub fn addLocal(self: *Self, allocator: std.mem.Allocator, candidate: Candidate) !usize {
        const index = self.locals.items.len;
        try self.locals.append(allocator, candidate);
        return index;
    }

    pub fn addRemote(self: *Self, allocator: std.mem.Allocator, candidate: Candidate) !usize {
        const index = self.remotes.items.len;
        try self.remotes.append(allocator, candidate);
        return index;
    }

    pub fn formPairs(self: *Self, allocator: std.mem.Allocator) !void {
        self.pairs.clearRetainingCapacity();
        self.selected_pair = null;

        for (self.locals.items, 0..) |local, local_index| {
            for (self.remotes.items, 0..) |remote, remote_index| {
                try self.pairs.append(allocator, .{
                    .local_index = local_index,
                    .remote_index = remote_index,
                    .priority = computePairPriority(local.priority, remote.priority),
                    .state = .waiting,
                    .nominated = false,
                });
            }
        }

        std.sort.heap(CandidatePair, self.pairs.items, {}, pairHigherPriority);
    }

    pub fn pairCount(self: Self) usize {
        return self.pairs.items.len;
    }

    pub fn pairAt(self: Self, index: usize) ?CandidatePair {
        if (index >= self.pairs.items.len) return null;
        return self.pairs.items[index];
    }

    pub fn selected(self: Self) ?CandidatePair {
        const index = self.selected_pair orelse return null;
        return self.pairs.items[index];
    }

    pub fn beginCheck(self: *Self, index: usize) CheckListError!void {
        var pair = try self.mutablePair(index);
        pair.state = switch (pair.state) {
            .frozen, .waiting => .in_progress,
            .in_progress => .in_progress,
            .succeeded => .succeeded,
            .failed => return error.FailedPair,
        };
    }

    pub fn fail(self: *Self, index: usize) CheckListError!void {
        var pair = try self.mutablePair(index);
        pair.state = .failed;
        pair.nominated = false;
        if (self.selected_pair == index) self.selected_pair = null;
    }

    /// Records remote nomination. ICE-lite never nominates on its own; success
    /// alone is not enough to select a pair.
    pub fn nominate(self: *Self, index: usize) CheckListError!bool {
        var pair = try self.mutablePair(index);
        if (pair.state == .failed) return error.FailedPair;
        pair.nominated = true;
        if (pair.state == .succeeded) {
            self.selected_pair = index;
            return true;
        }
        return false;
    }

    /// Marks a binding check successful and returns the selected pair only when
    /// the remote side has nominated it.
    pub fn onBindingSuccess(self: *Self, index: usize) CheckListError!?CandidatePair {
        var pair = try self.mutablePair(index);
        if (pair.state == .failed) return error.FailedPair;
        pair.state = .succeeded;
        if (!pair.nominated) return null;
        self.selected_pair = index;
        return pair.*;
    }

    fn mutablePair(self: *Self, index: usize) CheckListError!*CandidatePair {
        if (index >= self.pairs.items.len) return error.PairNotFound;
        return &self.pairs.items[index];
    }
};

fn pairHigherPriority(_: void, a: CandidatePair, b: CandidatePair) bool {
    if (a.priority != b.priority) return a.priority > b.priority;
    if (a.local_index != b.local_index) return a.local_index < b.local_index;
    return a.remote_index < b.remote_index;
}

fn ip4(a: u8, b: u8, c: u8, d: u8) [16]u8 {
    var out: [16]u8 = .{0} ** 16;
    out[0] = a;
    out[1] = b;
    out[2] = c;
    out[3] = d;
    return out;
}

fn cand(kind: CandidateKind, priority_bias: u16, foundation: Foundation) Candidate {
    return Candidate.init(
        kind,
        .udp,
        .ipv4,
        ip4(192, 0, 2, @intCast(foundation)),
        10_000 + @as(u16, @intCast(foundation)),
        foundation,
        priority_bias,
        1,
    );
}

test "candidate priority matches RFC example" {
    try testing.expectEqual(
        @as(u32, 2_130_706_431),
        computePriority(.host, 65_535, 1),
    );
}

test "host candidates rank above server-reflexive and relay candidates" {
    const host = computePriority(.host, 100, 1);
    const srflx = computePriority(.srflx, 65_535, 1);
    const relay = computePriority(.relay, 65_535, 1);

    try testing.expect(host > srflx);
    try testing.expect(srflx > relay);
}

test "formPairs sorts by pair priority descending" {
    var list = CheckList.init();
    defer list.deinit(testing.allocator);

    _ = try list.addLocal(testing.allocator, cand(.relay, 1, 1));
    _ = try list.addLocal(testing.allocator, cand(.host, 1, 2));
    _ = try list.addRemote(testing.allocator, cand(.relay, 1, 3));
    _ = try list.addRemote(testing.allocator, cand(.host, 1, 4));
    try list.formPairs(testing.allocator);

    try testing.expectEqual(@as(usize, 4), list.pairCount());
    const first = list.pairAt(0).?;
    const last = list.pairAt(3).?;

    try testing.expect(first.priority > last.priority);
    try testing.expectEqual(@as(usize, 1), first.local_index);
    try testing.expectEqual(@as(usize, 1), first.remote_index);
    try testing.expectEqual(@as(usize, 0), last.local_index);
    try testing.expectEqual(@as(usize, 0), last.remote_index);
}

test "nomination transitions require success and explicit remote nomination" {
    var list = CheckList.init();
    defer list.deinit(testing.allocator);

    _ = try list.addLocal(testing.allocator, cand(.host, 1, 1));
    _ = try list.addRemote(testing.allocator, cand(.host, 2, 2));
    try list.formPairs(testing.allocator);

    try testing.expectEqual(PairState.waiting, list.pairAt(0).?.state);
    try list.beginCheck(0);
    try testing.expectEqual(PairState.in_progress, list.pairAt(0).?.state);

    try testing.expectEqual(null, try list.onBindingSuccess(0));
    try testing.expectEqual(PairState.succeeded, list.pairAt(0).?.state);
    try testing.expect(list.selected() == null);

    try testing.expect(try list.nominate(0));
    const selected = list.selected().?;
    try testing.expect(selected.nominated);
    try testing.expectEqual(PairState.succeeded, selected.state);
}

test "binding success returns nominated pair when nomination is already recorded" {
    var list = CheckList.init();
    defer list.deinit(testing.allocator);

    _ = try list.addLocal(testing.allocator, cand(.host, 1, 1));
    _ = try list.addRemote(testing.allocator, cand(.host, 2, 2));
    try list.formPairs(testing.allocator);

    try testing.expect(!try list.nominate(0));
    const selected = (try list.onBindingSuccess(0)).?;
    try testing.expect(selected.nominated);
    try testing.expectEqual(PairState.succeeded, selected.state);
}
