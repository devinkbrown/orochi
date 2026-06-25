// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fault Loom — deterministic fault injection for tests and simulation.
//!
//! The active path is compile-time gated. Debug and test builds can arm named
//! sites or run a seeded campaign; release builds return without touching any
//! registry state.

const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;

pub const enabled = builtin.is_test or switch (builtin.mode) {
    .Debug => true,
    .ReleaseSafe => false,
    .ReleaseFast => false,
    .ReleaseSmall => false,
};

pub const Error = error{InvalidFaultSchedule};

pub const Campaign = struct {
    seed: u64,
    one_in: u32,
    err: anyerror = error.FaultLoomInjected,

    fn shouldFail(self: Campaign, site: []const u8) bool {
        if (self.one_in == 0) return false;
        const h = std.hash.Wyhash.hash(self.seed, site);
        return @mod(h, self.one_in) == 0;
    }
};

const Plan = struct {
    fail_on_nth: u64,
    hits: u64 = 0,
    err: anyerror,
};

const Decision = struct {
    fail: bool,
    err: anyerror = error.FaultLoomInjected,
};

pub const Registry = struct {
    plans: std.StringHashMapUnmanaged(Plan) = .empty,
    campaign: ?Campaign = null,

    pub fn deinit(self: *Registry, allocator: Allocator) void {
        if (!enabled) return;
        self.reset(allocator);
        self.plans.deinit(allocator);
        self.* = .{};
    }

    pub fn arm(
        self: *Registry,
        allocator: Allocator,
        site: []const u8,
        fail_on_nth: u64,
        err: anyerror,
    ) !void {
        if (!enabled) return;
        if (fail_on_nth == 0) return Error.InvalidFaultSchedule;

        if (self.plans.getPtr(site)) |plan| {
            plan.* = .{ .fail_on_nth = fail_on_nth, .err = err };
            return;
        }

        const owned_site = try allocator.dupe(u8, site);
        errdefer allocator.free(owned_site);
        try self.plans.put(allocator, owned_site, .{
            .fail_on_nth = fail_on_nth,
            .err = err,
        });
    }

    pub fn reset(self: *Registry, allocator: Allocator) void {
        if (!enabled) return;
        var it = self.plans.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        self.plans.clearRetainingCapacity();
        self.campaign = null;
    }

    pub fn setCampaign(self: *Registry, campaign: ?Campaign) void {
        if (!enabled) return;
        self.campaign = campaign;
    }

    pub fn shouldFail(self: *Registry, site: []const u8) bool {
        if (!enabled) return false;
        return self.next(site).fail;
    }

    pub fn maybeFail(
        self: *Registry,
        site: []const u8,
        comptime ErrSet: type,
    ) ErrSet!void {
        if (!enabled) return;
        const decision = self.next(site);
        if (decision.fail) return @errorCast(decision.err);
    }

    fn next(self: *Registry, site: []const u8) Decision {
        if (self.plans.getPtr(site)) |plan| {
            plan.hits += 1;
            return .{
                .fail = plan.hits == plan.fail_on_nth,
                .err = plan.err,
            };
        }

        if (self.campaign) |campaign| {
            return .{
                .fail = campaign.shouldFail(site),
                .err = campaign.err,
            };
        }

        return .{ .fail = false };
    }
};

const Global = if (enabled) struct {
    var mutex: std.Thread.Mutex = .{};
    var registry: Registry = .{};
} else struct {};

pub fn arm(
    allocator: Allocator,
    site: []const u8,
    fail_on_nth: u64,
    err: anyerror,
) !void {
    if (!enabled) return;
    Global.mutex.lock();
    defer Global.mutex.unlock();
    try Global.registry.arm(allocator, site, fail_on_nth, err);
}

pub fn reset(allocator: Allocator) void {
    if (!enabled) return;
    Global.mutex.lock();
    defer Global.mutex.unlock();
    Global.registry.reset(allocator);
}

pub fn setCampaign(campaign: ?Campaign) void {
    if (!enabled) return;
    Global.mutex.lock();
    defer Global.mutex.unlock();
    Global.registry.setCampaign(campaign);
}

pub fn shouldFail(comptime site: []const u8) bool {
    if (!enabled) return false;
    Global.mutex.lock();
    defer Global.mutex.unlock();
    return Global.registry.shouldFail(site);
}

pub fn maybeFail(comptime site: []const u8, comptime ErrSet: type) ErrSet!void {
    if (!enabled) return;
    Global.mutex.lock();
    defer Global.mutex.unlock();
    try Global.registry.maybeFail(site, ErrSet);
}

test "armed site fails on requested second hit" {
    var loom: Registry = .{};
    defer loom.deinit(std.testing.allocator);

    try loom.arm(std.testing.allocator, "journal.flush", 2, error.Injected);

    try loom.maybeFail("journal.flush", error{Injected});
    try std.testing.expectError(
        error.Injected,
        loom.maybeFail("journal.flush", error{Injected}),
    );
    try loom.maybeFail("journal.flush", error{Injected});
}

test "reset clears plans and counters" {
    var loom: Registry = .{};
    defer loom.deinit(std.testing.allocator);

    try loom.arm(std.testing.allocator, "cache.write", 2, error.Injected);
    try std.testing.expect(!loom.shouldFail("cache.write"));

    loom.reset(std.testing.allocator);
    try loom.arm(std.testing.allocator, "cache.write", 2, error.Injected);

    try std.testing.expect(!loom.shouldFail("cache.write"));
    try std.testing.expect(loom.shouldFail("cache.write"));
}

test "unarmed sites do not fail without campaign" {
    var loom: Registry = .{};
    defer loom.deinit(std.testing.allocator);

    try std.testing.expect(!loom.shouldFail("idle.unarmed"));
    try loom.maybeFail("idle.unarmed", error{Injected});
}

test "seeded campaign is deterministic" {
    var left: Registry = .{};
    var right: Registry = .{};
    defer left.deinit(std.testing.allocator);
    defer right.deinit(std.testing.allocator);

    const campaign: Campaign = .{
        .seed = 0xa11c_e5eed,
        .one_in = 3,
        .err = error.CampaignFault,
    };
    left.setCampaign(campaign);
    right.setCampaign(campaign);

    const sites = [_][]const u8{
        "raft.append",
        "media.packet",
        "timer.tick",
        "storage.compact",
        "presence.fanout",
    };

    for (sites) |site| {
        try std.testing.expectEqual(left.shouldFail(site), right.shouldFail(site));
    }
}
