//! Deterministic S2S session-migration state machine for Helix.
//!
//! This module is deliberately pure: it performs no I/O, owns no resources, and
//! imports only `std`. Callers provide all timing and epoch data through events.
//! The table is intentionally small so migration orchestration code can test
//! every allowed path and treat every other event ordering as a protocol bug.

const std = @import("std");
const testing = std.testing;

pub const State = enum {
    idle,
    offered,
    accepted,
    transferring,
    committed,
    cutover,
    done,
    aborted,

    pub fn isTerminal(state: State) bool {
        return switch (state) {
            .done, .aborted => true,
            .idle, .offered, .accepted, .transferring, .committed, .cutover => false,
        };
    }
};

pub const RequestMigrate = struct {
    epoch: u64,
    now_ms: i64,
    timeout_ms: i64,
};

pub const Event = union(enum) {
    request_migrate: RequestMigrate,
    peer_accept,
    peer_reject,
    capsule_sent,
    peer_confirmed,
    client_reclaimed,
    timeout,
    abort,
};

pub const TransitionError = error{InvalidTransition};

pub const Model = struct {
    state: State = .idle,
    epoch: u64 = 0,
    deadline_ms: i64 = 0,

    /// Creates the offered model exactly as if an idle model received
    /// `.request_migrate`.
    pub fn begin(epoch: u64, now_ms: i64, timeout_ms: i64) Model {
        return .{
            .state = .offered,
            .epoch = epoch,
            .deadline_ms = now_ms + timeout_ms,
        };
    }

    pub fn idle() Model {
        return .{};
    }

    pub fn transition(model: Model, event: Event) TransitionError!Model {
        if (model.state.isTerminal()) return error.InvalidTransition;

        return switch (event) {
            .timeout, .abort, .peer_reject => model.withState(.aborted),
            .request_migrate => |request| switch (model.state) {
                .idle => begin(request.epoch, request.now_ms, request.timeout_ms),
                .offered, .accepted, .transferring, .committed, .cutover => error.InvalidTransition,
                .done, .aborted => unreachable,
            },
            .peer_accept => switch (model.state) {
                .offered => model.withState(.accepted),
                .idle, .accepted, .transferring, .committed, .cutover => error.InvalidTransition,
                .done, .aborted => unreachable,
            },
            .capsule_sent => switch (model.state) {
                .accepted => model.withState(.transferring),
                .transferring => model,
                .idle, .offered, .committed, .cutover => error.InvalidTransition,
                .done, .aborted => unreachable,
            },
            .peer_confirmed => switch (model.state) {
                .transferring => model.withState(.committed),
                .idle, .offered, .accepted, .committed, .cutover => error.InvalidTransition,
                .done, .aborted => unreachable,
            },
            .client_reclaimed => switch (model.state) {
                .committed => model.withState(.cutover),
                .cutover => model.withState(.done),
                .idle, .offered, .accepted, .transferring => error.InvalidTransition,
                .done, .aborted => unreachable,
            },
        };
    }

    fn withState(model: Model, state: State) Model {
        return .{
            .state = state,
            .epoch = model.epoch,
            .deadline_ms = model.deadline_ms,
        };
    }
};

test "begin starts offered migration with deterministic deadline" {
    const model = Model.begin(42, 1_000, 250);

    try testing.expectEqual(State.offered, model.state);
    try testing.expectEqual(@as(u64, 42), model.epoch);
    try testing.expectEqual(@as(i64, 1_250), model.deadline_ms);
}

test "full happy path reaches done from idle" {
    var model = Model.idle();

    model = try Model.transition(model, .{ .request_migrate = .{
        .epoch = 7,
        .now_ms = 10,
        .timeout_ms = 90,
    } });
    try testing.expectEqual(State.offered, model.state);
    try testing.expectEqual(@as(u64, 7), model.epoch);
    try testing.expectEqual(@as(i64, 100), model.deadline_ms);

    model = try Model.transition(model, .peer_accept);
    try testing.expectEqual(State.accepted, model.state);

    model = try Model.transition(model, .capsule_sent);
    try testing.expectEqual(State.transferring, model.state);

    model = try Model.transition(model, .capsule_sent);
    try testing.expectEqual(State.transferring, model.state);

    model = try Model.transition(model, .peer_confirmed);
    try testing.expectEqual(State.committed, model.state);

    model = try Model.transition(model, .client_reclaimed);
    try testing.expectEqual(State.cutover, model.state);

    model = try Model.transition(model, .client_reclaimed);
    try testing.expectEqual(State.done, model.state);
    try testing.expectEqual(@as(u64, 7), model.epoch);
    try testing.expectEqual(@as(i64, 100), model.deadline_ms);
}

test "peer rejection aborts a non-terminal migration" {
    var model = Model.begin(9, 100, 5);
    model = try Model.transition(model, .peer_reject);

    try testing.expectEqual(State.aborted, model.state);
    try testing.expectEqual(@as(u64, 9), model.epoch);
    try testing.expectEqual(@as(i64, 105), model.deadline_ms);
}

test "timeout aborts from every non-terminal state" {
    const cases = [_]Model{
        Model.idle(),
        Model.begin(1, 10, 10),
        .{ .state = .accepted, .epoch = 1, .deadline_ms = 20 },
        .{ .state = .transferring, .epoch = 1, .deadline_ms = 20 },
        .{ .state = .committed, .epoch = 1, .deadline_ms = 20 },
        .{ .state = .cutover, .epoch = 1, .deadline_ms = 20 },
    };

    for (cases) |case| {
        const aborted = try Model.transition(case, .timeout);
        try testing.expectEqual(State.aborted, aborted.state);
        try testing.expectEqual(case.epoch, aborted.epoch);
        try testing.expectEqual(case.deadline_ms, aborted.deadline_ms);
    }
}

test "abort aborts from every non-terminal state" {
    const cases = [_]Model{
        Model.idle(),
        Model.begin(2, 10, 10),
        .{ .state = .accepted, .epoch = 2, .deadline_ms = 20 },
        .{ .state = .transferring, .epoch = 2, .deadline_ms = 20 },
        .{ .state = .committed, .epoch = 2, .deadline_ms = 20 },
        .{ .state = .cutover, .epoch = 2, .deadline_ms = 20 },
    };

    for (cases) |case| {
        const aborted = try Model.transition(case, .abort);
        try testing.expectEqual(State.aborted, aborted.state);
        try testing.expectEqual(case.epoch, aborted.epoch);
        try testing.expectEqual(case.deadline_ms, aborted.deadline_ms);
    }
}

test "invalid transition rejection preserves source model" {
    const model = Model.begin(11, 100, 10);

    try testing.expectError(error.InvalidTransition, Model.transition(model, .capsule_sent));
    try testing.expectEqual(State.offered, model.state);
    try testing.expectEqual(@as(u64, 11), model.epoch);
    try testing.expectEqual(@as(i64, 110), model.deadline_ms);
}

test "terminal states reject every event" {
    const events = [_]Event{
        .{ .request_migrate = .{ .epoch = 3, .now_ms = 0, .timeout_ms = 1 } },
        .peer_accept,
        .peer_reject,
        .capsule_sent,
        .peer_confirmed,
        .client_reclaimed,
        .timeout,
        .abort,
    };

    for ([_]State{ .done, .aborted }) |state| {
        const model = Model{ .state = state, .epoch = 3, .deadline_ms = 1 };
        for (events) |event| {
            try testing.expectError(error.InvalidTransition, Model.transition(model, event));
        }
    }
}

test "request_migrate is only accepted from idle" {
    const event = Event{ .request_migrate = .{
        .epoch = 99,
        .now_ms = 500,
        .timeout_ms = 100,
    } };

    const offered = try Model.transition(Model.idle(), event);
    try testing.expectEqual(State.offered, offered.state);
    try testing.expectEqual(@as(u64, 99), offered.epoch);
    try testing.expectEqual(@as(i64, 600), offered.deadline_ms);

    const non_idle = [_]Model{
        Model.begin(1, 1, 1),
        .{ .state = .accepted, .epoch = 1, .deadline_ms = 2 },
        .{ .state = .transferring, .epoch = 1, .deadline_ms = 2 },
        .{ .state = .committed, .epoch = 1, .deadline_ms = 2 },
        .{ .state = .cutover, .epoch = 1, .deadline_ms = 2 },
    };

    for (non_idle) |model| {
        try testing.expectError(error.InvalidTransition, Model.transition(model, event));
    }
}
