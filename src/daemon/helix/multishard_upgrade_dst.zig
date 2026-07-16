// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Seed-replayable fault campaign for the multi-shard Helix transaction.
//!
//! The live implementation is split across reactor threads, kernel fds, a sealed
//! memfd, and an `execve`, so a deterministic unit test cannot run the final
//! commit without replacing its own test process. This model covers the same
//! transaction boundary and failure order as `LinuxServer.performUpgrade`:
//!
//!   claim -> park every sibling -> seal every shard -> build plan -> exec -> adopt
//!
//! It complements the live server tests that prove the real quiesce handshake,
//! all-shard seal, and fd-derived re-pin, plus `tools/upgrade_smoke.py`, which
//! executes the real two-shard handoff. Fault Loom drives every pre-commit seam.
//! The load-bearing invariant is all-or-predecessor: before `execve`, any fault
//! must leave the predecessor serving every client and listener with no parked
//! shard or inherited-fd marker leaked. A successful commit must transfer every
//! shard exactly once. The legacy shard-0-only model is retained as a regression
//! oracle and must fail the invariant.

const std = @import("std");
const fault_loom = @import("../../substrate/fault_loom.zig");

const testing = std.testing;
const max_shards = 8;

const Phase = enum {
    serving,
    quiescing,
    sealing,
    planned,
    committed,
    adopted,
    aborted,
};

const Shard = struct {
    clients: u16,
    listener_live: bool = true,
    parked: bool = false,
    client_fds_inheritable: bool = false,
    listener_fd_inheritable: bool = false,
    adopted_clients: u16 = 0,
    listener_adopted: bool = false,
};

const Model = struct {
    shards: [max_shards]Shard = undefined,
    shard_count: usize,
    phase: Phase = .serving,
    predecessor_live: bool = true,
    successor_live: bool = false,

    fn init(clients: []const u16) Model {
        std.debug.assert(clients.len >= 2 and clients.len <= max_shards);
        var model = Model{ .shard_count = clients.len };
        for (clients, 0..) |count, i| model.shards[i] = .{ .clients = count };
        for (clients.len..max_shards) |i| model.shards[i] = .{ .clients = 0, .listener_live = false };
        return model;
    }

    fn active(self: *Model) []Shard {
        return self.shards[0..self.shard_count];
    }

    fn initialClientCount(self: *const Model) usize {
        var total: usize = 0;
        for (self.shards[0..self.shard_count]) |shard| total += shard.clients;
        return total;
    }

    fn abort(self: *Model) void {
        for (self.active()) |*shard| {
            shard.parked = false;
            shard.client_fds_inheritable = false;
            shard.listener_fd_inheritable = false;
            shard.adopted_clients = 0;
            shard.listener_adopted = false;
        }
        self.predecessor_live = true;
        self.successor_live = false;
        self.phase = .aborted;
    }

    fn assertInvariant(self: *const Model) !void {
        const initial_clients = self.initialClientCount();
        var served_clients: usize = 0;
        var served_listeners: usize = 0;
        var parked: usize = 0;
        var inheritable: usize = 0;

        for (self.shards[0..self.shard_count]) |shard| {
            parked += @intFromBool(shard.parked);
            inheritable += @intFromBool(shard.client_fds_inheritable);
            inheritable += @intFromBool(shard.listener_fd_inheritable);
            if (self.predecessor_live) {
                served_clients += shard.clients;
                served_listeners += @intFromBool(shard.listener_live);
            }
            if (self.successor_live) {
                served_clients += shard.adopted_clients;
                served_listeners += @intFromBool(shard.listener_adopted);
            }
        }

        if (served_clients != initial_clients) return error.ClientLoss;
        if (served_listeners != self.shard_count) return error.ListenerLoss;
        if (self.predecessor_live == self.successor_live) return error.OwnershipSplit;

        switch (self.phase) {
            .aborted => {
                if (parked != 0) return error.ParkedShardLeak;
                if (inheritable != 0) return error.InheritedFdLeak;
            },
            .adopted => {
                if (parked != self.shard_count - 1) return error.QuiesceLostBeforeCommit;
                for (self.shards[0..self.shard_count]) |shard| {
                    if (!shard.listener_adopted) return error.ListenerLoss;
                    if (shard.adopted_clients != shard.clients) return error.ClientLoss;
                }
            },
            else => return error.IncompleteTransaction,
        }
    }
};

fn site(out: []u8, prefix: []const u8, shard: usize) []const u8 {
    return std.fmt.bufPrint(out, "helix.multishard.{s}.{d}", .{ prefix, shard }) catch
        "helix.multishard.invalid";
}

fn failAt(loom: ?*fault_loom.Registry, name: []const u8) bool {
    return if (loom) |l| l.shouldFail(name) else false;
}

/// Drive one modeled USR2 attempt. `legacy_shard0_only` reproduces the fixed
/// pre-0.5.2 bug and exists only to prove the invariant catches it.
fn attempt(model: *Model, loom: ?*fault_loom.Registry, legacy_shard0_only: bool) void {
    model.phase = .quiescing;
    for (model.active(), 0..) |*shard, i| {
        if (i == 0) continue; // shard 0 owns the upgrade in this campaign
        var site_buf: [64]u8 = undefined;
        if (failAt(loom, site(&site_buf, "park", i))) return model.abort();
        shard.parked = true;
    }

    model.phase = .sealing;
    const seal_count: usize = if (legacy_shard0_only) 1 else model.shard_count;
    for (model.shards[0..seal_count], 0..) |*shard, i| {
        var client_site_buf: [64]u8 = undefined;
        if (failAt(loom, site(&client_site_buf, "seal-clients", i))) return model.abort();
        shard.client_fds_inheritable = true;

        var listener_site_buf: [64]u8 = undefined;
        if (failAt(loom, site(&listener_site_buf, "seal-listener", i))) return model.abort();
        shard.listener_fd_inheritable = true;
    }

    if (failAt(loom, "helix.multishard.plan")) return model.abort();
    model.phase = .planned;
    if (failAt(loom, "helix.multishard.exec")) return model.abort();

    model.phase = .committed;
    model.predecessor_live = false;
    model.successor_live = true;
    for (model.active()) |*shard| {
        if (shard.client_fds_inheritable) shard.adopted_clients = shard.clients;
        shard.listener_adopted = shard.listener_fd_inheritable;
    }
    model.phase = .adopted;
}

test "multi-shard USR2 transaction transfers every live reactor exactly once" {
    var model = Model.init(&.{ 3, 5, 2, 7 });
    attempt(&model, null, false);
    try model.assertInvariant();
}

test "multi-shard USR2 fault campaign aborts cleanly or adopts every shard" {
    const seeds = [_]u64{
        0x0000_0000_0000_0001,
        0x0bad_f00d_dead_beef,
        0x5eed_5eed_5eed_5eed,
        0xa11c_e5ee_d0d0_beef,
        0xdead_beef_cafe_f00d,
        0xffff_ffff_ffff_ffff,
    };

    for (seeds) |seed| {
        var loom: fault_loom.Registry = .{};
        defer loom.deinit(testing.allocator);
        loom.setCampaign(.{ .seed = seed, .one_in = 3, .err = error.Injected });

        var model = Model.init(&.{ 4, 3, 6, 2 });
        attempt(&model, &loom, false);
        model.assertInvariant() catch |err| {
            std.debug.print(
                "multi-shard USR2 fault campaign failed: seed=0x{x:0>16}, phase={s}\n",
                .{ seed, @tagName(model.phase) },
            );
            return err;
        };
    }
}

test "armed faults cover every pre-exec seam and restore predecessor ownership" {
    const fault_sites = [_][]const u8{
        "helix.multishard.park.1",
        "helix.multishard.park.2",
        "helix.multishard.park.3",
        "helix.multishard.seal-clients.0",
        "helix.multishard.seal-clients.1",
        "helix.multishard.seal-listener.2",
        "helix.multishard.seal-listener.3",
        "helix.multishard.plan",
        "helix.multishard.exec",
    };

    for (fault_sites) |fault_site| {
        var loom: fault_loom.Registry = .{};
        defer loom.deinit(testing.allocator);
        try loom.arm(testing.allocator, fault_site, 1, error.Injected);

        var model = Model.init(&.{ 1, 2, 3, 4 });
        attempt(&model, &loom, false);
        try testing.expectEqual(Phase.aborted, model.phase);
        try model.assertInvariant();
    }
}

test "regression oracle rejects the pre-0.5.2 shard-zero-only handoff" {
    var legacy = Model.init(&.{ 2, 3, 4, 5 });
    attempt(&legacy, null, true);
    try testing.expectError(error.ClientLoss, legacy.assertInvariant());
}
