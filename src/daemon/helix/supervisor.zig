// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helix supervisor state machine.
//!
//! The real `--supervisor` mode owns listener descriptors, a sealed memfd arena,
//! and an AF_UNIX SOCK_SEQPACKET control socket. This module keeps orchestration
//! testable by exposing a pure transition function; syscall-backed helpers are
//! Linux-gated wrappers over `handoff.zig`.

const std = @import("std");
const builtin = @import("builtin");

const attest = @import("attest.zig");
const handoff = @import("handoff.zig");

pub const Error = error{
    Unsupported,
    InvalidTransition,
    MissingCapsules,
    MissingControlSocket,
    MissingAttestation,
} || handoff.Error;

pub const State = enum {
    idle,
    accept_frozen,
    drained,
    serialized,
    fds_handed_off,
    awaiting_attestation,
    committed,
    rolled_back,
};

pub const Event = union(enum) {
    request_upgrade: u64,
    accept_frozen,
    drain_complete,
    capsules_serialized: u32,
    fds_handed_off: u32,
    await_attestation,
    attestation: attest.Message,
    attestation_timeout,
    worker_exit,
    operator_abort,
};

pub const Action = enum {
    none,
    freeze_accept,
    drain,
    serialize_capsules,
    pass_fds,
    await_attestation,
    commit,
    rollback,
};

pub const Model = struct {
    state: State = .idle,
    worker_epoch: u64 = 0,
    deadline_ms: i64 = 0,
    now_ms: i64 = 0,
    capsule_count: u32 = 0,
    fd_count: u32 = 0,

    pub fn begin(epoch: u64, now_ms: i64, timeout_ms: i64) Model {
        return .{
            .state = .idle,
            .worker_epoch = epoch,
            .deadline_ms = now_ms + timeout_ms,
            .now_ms = now_ms,
        };
    }

    pub fn snapshot(self: Model) attest.Snapshot {
        return .{
            .expected_epoch = self.worker_epoch,
            .deadline_ms = self.deadline_ms,
            .now_ms = self.now_ms,
            .capsules_exported = self.capsule_count,
            .fds_handed_off = self.fd_count,
        };
    }
};

pub const Step = struct {
    model: Model,
    action: Action,
};

pub fn transition(model: Model, event: Event) Error!Step {
    var next = model;
    const action: Action = switch (model.state) {
        .idle => switch (event) {
            .request_upgrade => |epoch| blk: {
                next.worker_epoch = epoch;
                next.state = .accept_frozen;
                break :blk .freeze_accept;
            },
            else => return error.InvalidTransition,
        },
        .accept_frozen => switch (event) {
            .accept_frozen => blk: {
                next.state = .drained;
                break :blk .drain;
            },
            .operator_abort, .worker_exit => blk: {
                next.state = .rolled_back;
                break :blk .rollback;
            },
            else => return error.InvalidTransition,
        },
        .drained => switch (event) {
            .drain_complete => blk: {
                next.state = .serialized;
                break :blk .serialize_capsules;
            },
            .operator_abort, .worker_exit => blk: {
                next.state = .rolled_back;
                break :blk .rollback;
            },
            else => return error.InvalidTransition,
        },
        .serialized => switch (event) {
            .capsules_serialized => |count| blk: {
                if (count == 0) return error.MissingCapsules;
                next.capsule_count = count;
                next.state = .fds_handed_off;
                break :blk .pass_fds;
            },
            .operator_abort, .worker_exit => blk: {
                next.state = .rolled_back;
                break :blk .rollback;
            },
            else => return error.InvalidTransition,
        },
        .fds_handed_off => switch (event) {
            .fds_handed_off => |count| blk: {
                next.fd_count = count;
                next.state = .awaiting_attestation;
                break :blk .await_attestation;
            },
            .operator_abort, .worker_exit => blk: {
                next.state = .rolled_back;
                break :blk .rollback;
            },
            else => return error.InvalidTransition,
        },
        .awaiting_attestation => switch (event) {
            .await_attestation => .await_attestation,
            .attestation => |msg| blk: {
                switch (attest.decide(next.snapshot(), msg)) {
                    .wait => break :blk .await_attestation,
                    .commit => {
                        next.state = .committed;
                        break :blk .commit;
                    },
                    .rollback => {
                        next.state = .rolled_back;
                        break :blk .rollback;
                    },
                }
            },
            .attestation_timeout, .worker_exit, .operator_abort => blk: {
                next.state = .rolled_back;
                break :blk .rollback;
            },
            else => return error.InvalidTransition,
        },
        .committed, .rolled_back => return error.InvalidTransition,
    };
    return .{ .model = next, .action = action };
}

pub const Runtime = struct {
    listeners: []const handoff.Fd = &.{},
    arena: ?handoff.Arena = null,
    control: ?handoff.SocketPair = null,

    pub fn initControl(self: *Runtime) Error!void {
        if (builtin.os.tag != .linux) return error.Unsupported;
        self.control = try handoff.socketPair();
    }

    pub fn createArena(self: *Runtime, name: []const u8) Error!void {
        if (builtin.os.tag != .linux) return error.Unsupported;
        self.arena = try handoff.Arena.create(name);
    }

    pub fn passFds(self: Runtime, fds: []const handoff.Fd, payload: []const u8) Error!usize {
        if (builtin.os.tag != .linux) return error.Unsupported;
        const control = self.control orelse return error.MissingControlSocket;
        return handoff.sendFdBatches(control.supervisor, fds, payload);
    }

    pub fn deinit(self: *Runtime) void {
        if (self.arena) |*arena| arena.close();
        if (self.control) |*control| control.close();
        self.* = .{};
    }
};

test "supervisor drives successful upgrade sequence" {
    var model = Model.begin(10, 1000, 5000);

    var step = try transition(model, .{ .request_upgrade = 10 });
    try std.testing.expectEqual(State.accept_frozen, step.model.state);
    try std.testing.expectEqual(Action.freeze_accept, step.action);

    step = try transition(step.model, .accept_frozen);
    try std.testing.expectEqual(State.drained, step.model.state);
    try std.testing.expectEqual(Action.drain, step.action);

    step = try transition(step.model, .drain_complete);
    try std.testing.expectEqual(State.serialized, step.model.state);
    try std.testing.expectEqual(Action.serialize_capsules, step.action);

    step = try transition(step.model, .{ .capsules_serialized = 4 });
    try std.testing.expectEqual(State.fds_handed_off, step.model.state);
    try std.testing.expectEqual(Action.pass_fds, step.action);

    step = try transition(step.model, .{ .fds_handed_off = 12 });
    try std.testing.expectEqual(State.awaiting_attestation, step.model.state);
    try std.testing.expectEqual(Action.await_attestation, step.action);

    model = step.model;
    const msg = attest.Message{
        .worker_epoch = 10,
        .monotonic_ms = 1100,
        .capsule_count = 4,
        .fd_count = 12,
        .verdict = .healthy,
    };
    step = try transition(model, .{ .attestation = msg });
    try std.testing.expectEqual(State.committed, step.model.state);
    try std.testing.expectEqual(Action.commit, step.action);
}

test "failed or late attestation rolls back" {
    var step = try transition(Model.begin(3, 0, 10), .{ .request_upgrade = 3 });
    step = try transition(step.model, .accept_frozen);
    step = try transition(step.model, .drain_complete);
    step = try transition(step.model, .{ .capsules_serialized = 1 });
    step = try transition(step.model, .{ .fds_handed_off = 1 });

    const failed = attest.Message{
        .worker_epoch = 3,
        .monotonic_ms = 2,
        .capsule_count = 1,
        .fd_count = 1,
        .verdict = .failed,
        .reason = .reactor_start,
    };
    step = try transition(step.model, .{ .attestation = failed });
    try std.testing.expectEqual(State.rolled_back, step.model.state);
    try std.testing.expectEqual(Action.rollback, step.action);
}

test "invalid ordering is rejected" {
    try std.testing.expectError(error.InvalidTransition, transition(Model.begin(1, 0, 10), .drain_complete));

    var step = try transition(Model.begin(1, 0, 10), .{ .request_upgrade = 1 });
    step = try transition(step.model, .accept_frozen);
    step = try transition(step.model, .drain_complete);
    try std.testing.expectError(error.MissingCapsules, transition(step.model, .{ .capsules_serialized = 0 }));
}
