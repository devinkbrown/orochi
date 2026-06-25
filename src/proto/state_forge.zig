// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! StateForge builds small protocol state-machine helpers from runtime tables.
//!
//! A machine is parameterized by exhaustive enum state and event types, then
//! initialized from a caller-owned transition slice. Runtime lookup stays in a
//! compact transition map, while reachability reports are computed on demand
//! with caller-supplied allocator storage.
const std = @import("std");

/// Returns a state machine type for one state enum and one event enum.
pub fn Machine(comptime State: type, comptime Event: type) type {
    comptime {
        requireExhaustiveEnum(State, "State");
        requireExhaustiveEnum(Event, "Event");
    }

    return struct {
        const Self = @This();

        const Key = struct {
            from: State,
            on: Event,
        };

        /// One legal transition in the machine table.
        pub const Transition = struct {
            from: State,
            on: Event,
            to: State,
        };

        /// Errors returned while building a transition table.
        pub const Error = std.mem.Allocator.Error || error{
            DuplicateTransition,
        };

        /// Allocator-owned set returned by reachability operations.
        pub const StateSet = struct {
            items: std.AutoHashMapUnmanaged(State, void) = .empty,

            /// Frees all storage owned by the set.
            pub fn deinit(self: *StateSet, allocator: std.mem.Allocator) void {
                self.items.deinit(allocator);
                self.* = undefined;
            }

            /// Returns whether `state` is present in the set.
            pub fn contains(self: *const StateSet, state: State) bool {
                return self.items.contains(state);
            }

            /// Returns the number of states in the set.
            pub fn count(self: *const StateSet) usize {
                return self.items.count();
            }

            fn add(self: *StateSet, allocator: std.mem.Allocator, state: State) std.mem.Allocator.Error!bool {
                const entry = try self.items.getOrPut(allocator, state);
                if (entry.found_existing) return false;
                entry.value_ptr.* = {};
                return true;
            }
        };

        transitions: std.ArrayListUnmanaged(Transition) = .empty,
        table: std.AutoHashMapUnmanaged(Key, State) = .empty,

        /// Builds a machine from the supplied transition table.
        pub fn init(allocator: std.mem.Allocator, transitions: []const Transition) Error!Self {
            var self: Self = .{};
            errdefer self.deinit(allocator);
            const transition_count = std.math.cast(u32, transitions.len) orelse return error.OutOfMemory;

            try self.transitions.ensureUnusedCapacity(allocator, transitions.len);
            try self.table.ensureUnusedCapacity(allocator, transition_count);

            for (transitions) |transition| {
                const entry = try self.table.getOrPut(allocator, .{
                    .from = transition.from,
                    .on = transition.on,
                });
                if (entry.found_existing) return error.DuplicateTransition;
                entry.value_ptr.* = transition.to;
                self.transitions.appendAssumeCapacity(transition);
            }

            return self;
        }

        /// Frees all storage owned by the machine.
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.transitions.deinit(allocator);
            self.table.deinit(allocator);
            self.* = undefined;
        }

        /// Returns the next state for `cur` and `ev`, or null when illegal.
        pub fn step(self: *const Self, cur: State, ev: Event) ?State {
            return self.table.get(.{
                .from = cur,
                .on = ev,
            });
        }

        /// Returns every state reachable from `from`, including `from`.
        pub fn reachable(self: *const Self, allocator: std.mem.Allocator, from: State) std.mem.Allocator.Error!StateSet {
            var reached: StateSet = .{};
            errdefer reached.deinit(allocator);

            var queue = std.ArrayListUnmanaged(State).empty;
            defer queue.deinit(allocator);

            _ = try reached.add(allocator, from);
            try queue.append(allocator, from);

            var cursor: usize = 0;
            while (cursor < queue.items.len) : (cursor += 1) {
                const cur = queue.items[cursor];
                for (self.transitions.items) |transition| {
                    if (transition.from != cur) continue;
                    if (try reached.add(allocator, transition.to)) {
                        try queue.append(allocator, transition.to);
                    }
                }
            }

            return reached;
        }

        /// Returns all enum states that cannot be reached from `from`.
        pub fn unreachableFrom(self: *const Self, allocator: std.mem.Allocator, from: State) std.mem.Allocator.Error!StateSet {
            var reached = try self.reachable(allocator, from);
            defer reached.deinit(allocator);

            var missing: StateSet = .{};
            errdefer missing.deinit(allocator);

            inline for (std.meta.fields(State)) |field| {
                const state: State = @field(State, field.name);
                if (!reached.contains(state)) {
                    _ = try missing.add(allocator, state);
                }
            }

            return missing;
        }

        /// Returns whether `state` has no legal outgoing transition.
        pub fn isTerminal(self: *const Self, state: State) bool {
            for (self.transitions.items) |transition| {
                if (transition.from == state) return false;
            }
            return true;
        }
    };
}

fn requireExhaustiveEnum(comptime T: type, comptime label: []const u8) void {
    switch (@typeInfo(T)) {
        .@"enum" => |info| {
            if (!info.is_exhaustive) {
                @compileError(label ++ " must be an exhaustive enum");
            }
        },
        else => @compileError(label ++ " must be an enum"),
    }
}

const testing = std.testing;

const RegistrationState = enum {
    start,
    nick_seen,
    user_seen,
    registered,
    maintenance,
};

const RegistrationEvent = enum {
    nick,
    user,
    accept,
};

const RegistrationMachine = Machine(RegistrationState, RegistrationEvent);

const registration_transitions = [_]RegistrationMachine.Transition{
    .{ .from = .start, .on = .nick, .to = .nick_seen },
    .{ .from = .nick_seen, .on = .user, .to = .user_seen },
    .{ .from = .user_seen, .on = .accept, .to = .registered },
};

fn buildRegistrationMachine() !RegistrationMachine {
    return RegistrationMachine.init(testing.allocator, &registration_transitions);
}

test "IRC registration follows the legal path" {
    var machine = try buildRegistrationMachine();
    defer machine.deinit(testing.allocator);

    const after_nick = machine.step(.start, .nick);
    const after_user = machine.step(after_nick.?, .user);
    const after_accept = machine.step(after_user.?, .accept);

    try testing.expectEqual(@as(?RegistrationState, .nick_seen), after_nick);
    try testing.expectEqual(@as(?RegistrationState, .user_seen), after_user);
    try testing.expectEqual(@as(?RegistrationState, .registered), after_accept);
}

test "illegal registration jumps return null" {
    var machine = try buildRegistrationMachine();
    defer machine.deinit(testing.allocator);

    try testing.expectEqual(@as(?RegistrationState, null), machine.step(.start, .user));
    try testing.expectEqual(@as(?RegistrationState, null), machine.step(.nick_seen, .accept));
    try testing.expectEqual(@as(?RegistrationState, null), machine.step(.registered, .nick));
}

test "terminal detection marks states without outgoing transitions" {
    var machine = try buildRegistrationMachine();
    defer machine.deinit(testing.allocator);

    try testing.expect(!machine.isTerminal(.start));
    try testing.expect(!machine.isTerminal(.nick_seen));
    try testing.expect(machine.isTerminal(.registered));
    try testing.expect(machine.isTerminal(.maintenance));
}

test "unreachable states are reported" {
    var machine = try buildRegistrationMachine();
    defer machine.deinit(testing.allocator);

    var reached = try machine.reachable(testing.allocator, .start);
    defer reached.deinit(testing.allocator);
    var missing = try machine.unreachableFrom(testing.allocator, .start);
    defer missing.deinit(testing.allocator);

    try testing.expect(reached.contains(.start));
    try testing.expect(reached.contains(.registered));
    try testing.expect(!reached.contains(.maintenance));
    try testing.expectEqual(@as(usize, 4), reached.count());

    try testing.expect(missing.contains(.maintenance));
    try testing.expectEqual(@as(usize, 1), missing.count());
}
