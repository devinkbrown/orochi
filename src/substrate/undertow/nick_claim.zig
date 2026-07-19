// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Network-wide NICK claim MV-register.
//!
//! The register is pure state: every nick maps to active `{owner UID, HLC}`
//! claims plus timestamped per-owner releases. Merging is a set union with
//! deterministic pruning, so operation delivery order does not affect the
//! resolved winner. Claim conflicts rename losers to their own UID.
const std = @import("std");

const clock = @import("clock.zig");
const uid_alloc = @import("uid_alloc.zig");

pub const Hlc = clock.Hlc;
pub const Uid = uid_alloc.Uid;

pub const Claim = struct {
    owner_uid: Uid,
    hlc: Hlc,
};

pub const ClaimOutcome = struct {
    winner_uid: Uid,
    loser_must_rename: ?Uid = null,
};

pub const Resolution = struct {
    winner_uid: Uid,
    winner_hlc: Hlc,
    contender_count: usize,
};

const Release = struct {
    owner_uid: Uid,
    hlc: Hlc,
};

const Entry = struct {
    claims: std.ArrayList(Claim) = .empty,
    releases: std.ArrayList(Release) = .empty,

    fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        self.claims.deinit(allocator);
        self.releases.deinit(allocator);
    }

    fn clone(self: *const Entry, allocator: std.mem.Allocator) !Entry {
        var out = Entry{};
        errdefer out.deinit(allocator);
        try out.claims.appendSlice(allocator, self.claims.items);
        try out.releases.appendSlice(allocator, self.releases.items);
        return out;
    }

    fn mergeFrom(self: *Entry, allocator: std.mem.Allocator, other: *const Entry) !void {
        for (other.releases.items) |release| {
            try self.upsertRelease(allocator, release);
        }
        for (other.claims.items) |claim_value| {
            try self.upsertClaim(allocator, claim_value);
        }
        self.pruneReleased();
    }

    fn upsertClaim(self: *Entry, allocator: std.mem.Allocator, claim_value: Claim) !void {
        if (self.releaseFor(claim_value.owner_uid)) |release| {
            if (Hlc.compare(release.hlc, claim_value.hlc) == .gt) return;
        }

        if (self.findClaimIndex(claim_value.owner_uid)) |idx| {
            if (claimWins(claim_value, self.claims.items[idx])) {
                self.claims.items[idx] = claim_value;
            }
            return;
        }

        try self.claims.append(allocator, claim_value);
    }

    fn upsertRelease(self: *Entry, allocator: std.mem.Allocator, release: Release) !void {
        if (self.findReleaseIndex(release.owner_uid)) |idx| {
            if (Hlc.compare(release.hlc, self.releases.items[idx].hlc) == .gt) {
                self.releases.items[idx] = release;
            }
            return;
        }

        try self.releases.append(allocator, release);
    }

    fn pruneReleased(self: *Entry) void {
        var idx: usize = 0;
        while (idx < self.claims.items.len) {
            const claim_value = self.claims.items[idx];
            const release = self.releaseFor(claim_value.owner_uid) orelse {
                idx += 1;
                continue;
            };
            if (Hlc.compare(release.hlc, claim_value.hlc) == .gt) {
                _ = self.claims.swapRemove(idx);
            } else {
                idx += 1;
            }
        }
    }

    fn resolution(self: *const Entry) ?Resolution {
        const winner = self.winningClaim() orelse return null;
        return .{
            .winner_uid = winner.owner_uid,
            .winner_hlc = winner.hlc,
            .contender_count = self.claims.items.len,
        };
    }

    fn winningClaim(self: *const Entry) ?Claim {
        var winner: ?Claim = null;
        for (self.claims.items) |claim_value| {
            if (winner == null or claimWins(claim_value, winner.?)) {
                winner = claim_value;
            }
        }
        return winner;
    }

    fn releaseFor(self: *const Entry, owner_uid: Uid) ?Release {
        if (self.findReleaseIndex(owner_uid)) |idx| return self.releases.items[idx];
        return null;
    }

    fn findClaimIndex(self: *const Entry, owner_uid: Uid) ?usize {
        for (self.claims.items, 0..) |claim_value, idx| {
            if (uidEql(claim_value.owner_uid, owner_uid)) return idx;
        }
        return null;
    }

    fn findReleaseIndex(self: *const Entry, owner_uid: Uid) ?usize {
        for (self.releases.items, 0..) |release, idx| {
            if (uidEql(release.owner_uid, owner_uid)) return idx;
        }
        return null;
    }

    fn eql(a: *const Entry, b: *const Entry) bool {
        if (a.claims.items.len != b.claims.items.len) return false;
        if (a.releases.items.len != b.releases.items.len) return false;

        for (a.claims.items) |claim_value| {
            if (!containsClaim(b.claims.items, claim_value)) return false;
        }
        for (a.releases.items) |release| {
            if (!containsRelease(b.releases.items, release)) return false;
        }
        return true;
    }
};

pub const NickClaimRegister = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    by_nick: std.StringHashMap(Entry),

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .by_nick = std.StringHashMap(Entry).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.by_nick.iterator();
        while (it.next()) |map_entry| {
            self.allocator.free(map_entry.key_ptr.*);
            map_entry.value_ptr.deinit(self.allocator);
        }
        self.by_nick.deinit();
    }

    pub fn claim(self: *Self, nick: []const u8, owner_uid: Uid, hlc: Hlc) !ClaimOutcome {
        const entry = try self.ensureEntry(nick);
        const before = entry.winningClaim();
        try entry.upsertClaim(self.allocator, .{ .owner_uid = owner_uid, .hlc = hlc });
        entry.pruneReleased();

        const winner = entry.winningClaim().?;
        return .{
            .winner_uid = winner.owner_uid,
            .loser_must_rename = loserAfterClaim(owner_uid, before, winner),
        };
    }

    pub fn release(self: *Self, nick: []const u8, owner_uid: Uid, hlc: Hlc) !void {
        const entry = try self.ensureEntry(nick);
        try entry.upsertRelease(self.allocator, .{ .owner_uid = owner_uid, .hlc = hlc });
        entry.pruneReleased();
    }

    pub fn resolve(self: *const Self, nick: []const u8) ?Resolution {
        const entry = self.by_nick.get(nick) orelse return null;
        return entry.resolution();
    }

    pub fn merge(self: *Self, other: *const Self) !void {
        var it = other.by_nick.iterator();
        while (it.next()) |other_map_entry| {
            const entry = try self.ensureEntry(other_map_entry.key_ptr.*);
            try entry.mergeFrom(self.allocator, other_map_entry.value_ptr);
        }
    }

    pub fn clone(self: *const Self) !Self {
        var out = Self.init(self.allocator);
        errdefer out.deinit();

        var it = self.by_nick.iterator();
        while (it.next()) |map_entry| {
            const key = try out.allocator.dupe(u8, map_entry.key_ptr.*);
            errdefer out.allocator.free(key);
            var entry = try map_entry.value_ptr.clone(out.allocator);
            errdefer entry.deinit(out.allocator);
            try out.by_nick.put(key, entry);
        }

        return out;
    }

    pub fn eql(a: *const Self, b: *const Self) bool {
        if (a.by_nick.count() != b.by_nick.count()) return false;

        var it = a.by_nick.iterator();
        while (it.next()) |map_entry| {
            const other = b.by_nick.get(map_entry.key_ptr.*) orelse return false;
            if (!Entry.eql(map_entry.value_ptr, &other)) return false;
        }
        return true;
    }

    fn ensureEntry(self: *Self, nick: []const u8) !*Entry {
        if (self.by_nick.getPtr(nick)) |entry| return entry;

        const owned_nick = try self.allocator.dupe(u8, nick);
        errdefer self.allocator.free(owned_nick);
        var entry = Entry{};
        errdefer entry.deinit(self.allocator);
        try self.by_nick.put(owned_nick, entry);
        return self.by_nick.getPtr(owned_nick).?;
    }
};

pub const Register = NickClaimRegister;

fn loserAfterClaim(owner_uid: Uid, before: ?Claim, winner: Claim) ?Uid {
    if (uidEql(winner.owner_uid, owner_uid)) {
        if (before) |prior| {
            if (!uidEql(prior.owner_uid, winner.owner_uid)) return prior.owner_uid;
        }
        return null;
    }

    return owner_uid;
}

fn claimWins(candidate: Claim, current: Claim) bool {
    switch (Hlc.compare(candidate.hlc, current.hlc)) {
        .gt => return true,
        .lt => return false,
        .eq => {},
    }
    return uidLessThan(candidate.owner_uid, current.owner_uid);
}

fn containsClaim(items: []const Claim, needle: Claim) bool {
    for (items) |item| {
        if (uidEql(item.owner_uid, needle.owner_uid) and std.meta.eql(item.hlc, needle.hlc)) {
            return true;
        }
    }
    return false;
}

fn containsRelease(items: []const Release, needle: Release) bool {
    for (items) |item| {
        if (uidEql(item.owner_uid, needle.owner_uid) and std.meta.eql(item.hlc, needle.hlc)) {
            return true;
        }
    }
    return false;
}

fn uidEql(a: Uid, b: Uid) bool {
    return std.mem.eql(u8, a[0..], b[0..]);
}

fn uidLessThan(a: Uid, b: Uid) bool {
    return std.mem.order(u8, a[0..], b[0..]) == .lt;
}

fn expectUid(expected: Uid, actual: Uid) !void {
    try std.testing.expectEqualSlices(u8, expected[0..], actual[0..]);
}

fn expectOptionalUid(expected: Uid, actual: ?Uid) !void {
    try std.testing.expect(actual != null);
    try expectUid(expected, actual.?);
}

test "concurrent claims pick a stable winner by HLC then UID" {
    const allocator = std.testing.allocator;
    var claims = NickClaimRegister.init(allocator);
    defer claims.deinit();

    const low_uid = uid_alloc.generate(1, 1);
    const high_uid = uid_alloc.generate(2, 1);
    const early = try Hlc.init(1000, 0);
    const late = try Hlc.init(1001, 0);

    _ = try claims.claim("Kain", low_uid, early);
    const later_outcome = try claims.claim("Kain", high_uid, late);
    try expectUid(high_uid, later_outcome.winner_uid);
    try expectOptionalUid(low_uid, later_outcome.loser_must_rename);

    const resolved = claims.resolve("Kain").?;
    try expectUid(high_uid, resolved.winner_uid);
    try std.testing.expectEqual(@as(usize, 2), resolved.contender_count);

    var tie = NickClaimRegister.init(allocator);
    defer tie.deinit();

    const same_time = try Hlc.init(2000, 4);
    _ = try tie.claim("Kain", high_uid, same_time);
    const tie_outcome = try tie.claim("Kain", low_uid, same_time);
    try expectUid(low_uid, tie_outcome.winner_uid);
    try expectOptionalUid(high_uid, tie_outcome.loser_must_rename);
}

test "loser renames to UID and release exposes remaining winner" {
    const allocator = std.testing.allocator;
    var claims = NickClaimRegister.init(allocator);
    defer claims.deinit();

    const first = uid_alloc.generate(10, 1);
    const second = uid_alloc.generate(20, 1);
    const t1 = try Hlc.init(10, 0);
    const t2 = try Hlc.init(11, 0);
    const t3 = try Hlc.init(12, 0);
    const t4 = try Hlc.init(13, 0);

    _ = try claims.claim("onyx", first, t1);
    const outcome = try claims.claim("onyx", second, t2);
    try expectUid(second, outcome.winner_uid);
    try expectOptionalUid(first, outcome.loser_must_rename);

    try claims.release("onyx", second, t3);
    try expectUid(first, claims.resolve("onyx").?.winner_uid);

    try claims.release("onyx", first, t4);
    try std.testing.expect(claims.resolve("onyx") == null);
}

test "merge is commutative and idempotent" {
    const allocator = std.testing.allocator;
    var left_source = NickClaimRegister.init(allocator);
    defer left_source.deinit();
    var right_source = NickClaimRegister.init(allocator);
    defer right_source.deinit();

    const first = uid_alloc.generate(7, 1);
    const second = uid_alloc.generate(8, 1);
    const first_hlc = try Hlc.init(50, 0);
    const second_hlc = try Hlc.init(51, 0);

    _ = try left_source.claim("mesh", first, first_hlc);
    _ = try right_source.claim("mesh", second, second_hlc);

    var left_then_right = try left_source.clone();
    defer left_then_right.deinit();
    try left_then_right.merge(&right_source);

    var right_then_left = try right_source.clone();
    defer right_then_left.deinit();
    try right_then_left.merge(&left_source);

    try std.testing.expect(NickClaimRegister.eql(&left_then_right, &right_then_left));
    try expectUid(second, left_then_right.resolve("mesh").?.winner_uid);

    var before_idempotent = try left_then_right.clone();
    defer before_idempotent.deinit();
    try left_then_right.merge(&right_source);
    try std.testing.expect(NickClaimRegister.eql(&left_then_right, &before_idempotent));
}
