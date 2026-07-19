// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded durable accepted-event authority for MESSAGE_V2 anti-entropy.
//!
//! Each row retains the exact canonical origin-signed wire and the sorted set
//! of nodes known to have durably accepted it. There is deliberately no TTL or
//! capacity eviction: until an authoritative membership epoch can prove that a
//! node is retired, forgetting a row could permanently partition a late peer.
//! Callers therefore reserve here before local publication or ACK emission and
//! fail closed when the configured bound is exhausted.
//!
//! The event-time required-node snapshot is supplied by the secured membership
//! authority and must contain the accepting node plus at least one explicitly
//! configured peer. Empty trust-root/TOFU configuration is not converted into a
//! local-only fallback. Once every required node confirms, the full wire retires;
//! RVG2 remains the mandatory retained replay/equivocation authority for that ID.

const std = @import("std");
const message_relay_v2 = @import("../substrate/undertow/message_relay_v2.zig");

pub const RelayId = message_relay_v2.RelayId;

pub const default_max_rows: usize = 8192;
pub const default_max_confirmed_nodes_per_row: usize = 256;
pub const default_max_cursor_nodes: usize = 256;
pub const default_max_wire_bytes: usize = 1024 * 1024;
pub const default_max_aggregate_bytes: usize = 32 * 1024 * 1024;
pub const hard_max_rows: usize = 65_536;
pub const hard_max_confirmed_nodes_per_row: usize = 4096;
pub const hard_max_cursor_nodes: usize = 4096;
pub const hard_max_wire_bytes: usize = 1024 * 1024;
pub const hard_max_aggregate_bytes: usize = 64 * 1024 * 1024;
pub const hard_max_checkpoint_bytes: usize = 64 * 1024 * 1024;

pub const Config = struct {
    max_rows: usize = default_max_rows,
    max_confirmed_nodes_per_row: usize = default_max_confirmed_nodes_per_row,
    max_cursor_nodes: usize = default_max_cursor_nodes,
    max_wire_bytes: usize = default_max_wire_bytes,
    max_aggregate_bytes: usize = default_max_aggregate_bytes,

    fn valid(self: Config) bool {
        return self.max_rows > 0 and self.max_rows <= hard_max_rows and
            self.max_confirmed_nodes_per_row > 0 and
            self.max_confirmed_nodes_per_row <= hard_max_confirmed_nodes_per_row and
            self.max_cursor_nodes > 0 and self.max_cursor_nodes <= hard_max_cursor_nodes and
            self.max_wire_bytes > 0 and self.max_wire_bytes <= hard_max_wire_bytes and
            self.max_aggregate_bytes > 0 and
            self.max_aggregate_bytes <= hard_max_aggregate_bytes;
    }

    fn eql(a: Config, b: Config) bool {
        return a.max_rows == b.max_rows and
            a.max_confirmed_nodes_per_row == b.max_confirmed_nodes_per_row and
            a.max_cursor_nodes == b.max_cursor_nodes and
            a.max_wire_bytes == b.max_wire_bytes and
            a.max_aggregate_bytes == b.max_aggregate_bytes;
    }
};

pub const ReserveOutcome = enum {
    inserted,
    exact_duplicate,
    conflict,
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidConfig,
    InvalidNode,
    InvalidMembership,
    InvalidWire,
    RelayIdMismatch,
    NotFound,
    NodeNotRequired,
    PreparedMutationActive,
    CapacityExceeded,
    BadMagic,
    UnsupportedVersion,
    UnknownFlags,
    ConfigMismatch,
    Truncated,
    TrailingBytes,
    ChecksumMismatch,
    DuplicateEntry,
    DuplicateNode,
    NonCanonicalOrder,
    CheckpointTooLarge,
    CounterMismatch,
    CursorTargetMissing,
    InvalidState,
};

const Row = struct {
    relay_id: RelayId,
    origin_pubkey: [message_relay_v2.pubkey_len]u8,
    origin_node: u64,
    hlc: u64,
    wire: []u8,
    required_nodes: std.ArrayListUnmanaged(u64) = .empty,
    confirmed_nodes: std.ArrayListUnmanaged(u64) = .empty,
    excluded_once_nodes: std.ArrayListUnmanaged(u64) = .empty,

    fn deinit(self: *Row, allocator: std.mem.Allocator) void {
        allocator.free(self.wire);
        self.required_nodes.deinit(allocator);
        self.confirmed_nodes.deinit(allocator);
        self.excluded_once_nodes.deinit(allocator);
        self.* = undefined;
    }
};

pub const RowView = struct {
    relay_id: RelayId,
    origin_pubkey: [message_relay_v2.pubkey_len]u8,
    origin_node: u64,
    hlc: u64,
    wire: []const u8,
    required_nodes: []const u64,
    confirmed_nodes: []const u64,
    excluded_once_nodes: []const u64,
};

pub const PageItem = struct {
    relay_id: RelayId,
    origin_pubkey: [message_relay_v2.pubkey_len]u8,
    origin_node: u64,
    hlc: u64,
    wire: []const u8,
};

const CursorEntry = struct {
    node: u64,
    /// The last origin considered for this target. The next page starts at the
    /// first lexicographically greater origin and wraps once, which provides
    /// fairness without ever stepping past that origin's lowest missing HLC.
    after_origin_pubkey: [message_relay_v2.pubkey_len]u8,
};

pub const PrepareAcceptedResult = union(enum) {
    ready: PreparedAccepted,
    conflict,
};

const AcceptedAction = union(enum) {
    no_op,
    insert: Row,
    add_exclusion: struct {
        row_index: usize,
        insert_index: usize,
        node: u64,
    },
};

/// Fully allocated accepted-event change waiting to join replay, Lotus, outbox,
/// and attachment-spool preparation. `commit` is allocation-free and cannot
/// fail. Keep one mutable value and always install `defer plan.deinit()`.
pub const PreparedAccepted = struct {
    const State = enum { prepared, committed, aborted };

    log: *EventLog,
    expected_epoch: u64,
    outcome_value: ReserveOutcome,
    action: AcceptedAction,
    state: State = .prepared,

    pub fn outcome(self: *const PreparedAccepted) ReserveOutcome {
        return self.outcome_value;
    }

    pub fn commit(self: *PreparedAccepted) ReserveOutcome {
        std.debug.assert(self.state == .prepared);
        std.debug.assert(self.log.prepared_active);
        std.debug.assert(self.log.mutation_epoch == self.expected_epoch);
        switch (self.action) {
            .no_op => {},
            .insert => |row| {
                const index = lowerBoundRows(self.log.rows.items, row.relay_id);
                self.log.rows.appendAssumeCapacity(undefined);
                var cursor = self.log.rows.items.len - 1;
                while (cursor > index) : (cursor -= 1)
                    self.log.rows.items[cursor] = self.log.rows.items[cursor - 1];
                self.log.rows.items[index] = row;
                self.log.aggregate_bytes += rowAggregateBytes(row);
                self.log.checkpoint_body_bytes += rowBodyBytes(row);
                self.action = .no_op;
            },
            .add_exclusion => |add| {
                const row = &self.log.rows.items[add.row_index];
                insertNodeAssumeCapacity(&row.excluded_once_nodes, add.insert_index, add.node);
                self.log.aggregate_bytes += @sizeOf(u64);
                self.log.checkpoint_body_bytes += @sizeOf(u64);
            },
        }
        self.log.prepared_active = false;
        self.log.bumpEpoch();
        self.state = .committed;
        return self.outcome_value;
    }

    pub fn abort(self: *PreparedAccepted) void {
        if (self.state != .prepared) return;
        switch (self.action) {
            .insert => |*row| row.deinit(self.log.allocator),
            else => {},
        }
        std.debug.assert(self.log.prepared_active);
        self.log.prepared_active = false;
        self.state = .aborted;
    }

    pub fn deinit(self: *PreparedAccepted) void {
        if (self.state == .prepared) self.abort();
        self.* = undefined;
    }
};

pub const ConfirmationOutcome = enum {
    already_confirmed,
    confirmed,
    confirmed_and_retired,
};

const ConfirmationAction = union(enum) {
    no_op,
    add: struct {
        row_index: usize,
        confirmed_index: usize,
        excluded_index: ?usize,
        node: u64,
    },
    retire_row: usize,
};

/// Prepared authenticated durable-ACK consequence. Authentication and binding
/// of `confirmed_node` to the secured peer happen above this leaf.
pub const PreparedConfirmation = struct {
    const State = enum { prepared, committed, aborted };

    log: *EventLog,
    expected_epoch: u64,
    outcome_value: ConfirmationOutcome,
    action: ConfirmationAction,
    state: State = .prepared,

    pub fn outcome(self: *const PreparedConfirmation) ConfirmationOutcome {
        return self.outcome_value;
    }

    pub fn commit(self: *PreparedConfirmation) ConfirmationOutcome {
        std.debug.assert(self.state == .prepared);
        std.debug.assert(self.log.prepared_active);
        std.debug.assert(self.log.mutation_epoch == self.expected_epoch);
        switch (self.action) {
            .no_op => {},
            .add => |add| {
                const row = &self.log.rows.items[add.row_index];
                if (add.excluded_index) |excluded_index| {
                    removeNodeAt(&row.excluded_once_nodes, excluded_index);
                } else {
                    self.log.aggregate_bytes += @sizeOf(u64);
                    self.log.checkpoint_body_bytes += @sizeOf(u64);
                }
                insertNodeAssumeCapacity(&row.confirmed_nodes, add.confirmed_index, add.node);
            },
            .retire_row => |row_index| self.log.removeRowAt(row_index),
        }
        self.log.prepared_active = false;
        self.log.bumpEpoch();
        self.state = .committed;
        return self.outcome_value;
    }

    pub fn abort(self: *PreparedConfirmation) void {
        if (self.state != .prepared) return;
        std.debug.assert(self.log.prepared_active);
        self.log.prepared_active = false;
        self.state = .aborted;
    }

    pub fn deinit(self: *PreparedConfirmation) void {
        if (self.state == .prepared) self.abort();
        self.* = undefined;
    }
};

pub const NodeRetirementResult = struct {
    rows_changed: usize,
    rows_retired: usize,
    cursor_removed: bool,
};

/// Explicit configuration-authorized membership retirement. This leaf cannot
/// authenticate configuration; callers must prepare this only after validating
/// a signed/configured removal, never from liveness or a TTL.
pub const PreparedNodeRetirement = struct {
    const State = enum { prepared, committed, aborted };

    log: *EventLog,
    expected_epoch: u64,
    node: u64,
    state: State = .prepared,

    pub fn commit(self: *PreparedNodeRetirement) NodeRetirementResult {
        std.debug.assert(self.state == .prepared);
        std.debug.assert(self.log.prepared_active);
        std.debug.assert(self.log.mutation_epoch == self.expected_epoch);
        var result: NodeRetirementResult = .{
            .rows_changed = 0,
            .rows_retired = 0,
            .cursor_removed = false,
        };
        var row_index: usize = 0;
        while (row_index < self.log.rows.items.len) {
            const row = &self.log.rows.items[row_index];
            const required_index = lowerBoundNodes(row.required_nodes.items, self.node);
            if (required_index == row.required_nodes.items.len or
                row.required_nodes.items[required_index] != self.node)
            {
                row_index += 1;
                continue;
            }
            removeNodeAt(&row.required_nodes, required_index);
            self.log.aggregate_bytes -= @sizeOf(u64);
            self.log.checkpoint_body_bytes -= @sizeOf(u64);
            if (nodeIndex(row.confirmed_nodes.items, self.node)) |index| {
                removeNodeAt(&row.confirmed_nodes, index);
                self.log.aggregate_bytes -= @sizeOf(u64);
                self.log.checkpoint_body_bytes -= @sizeOf(u64);
            }
            if (nodeIndex(row.excluded_once_nodes.items, self.node)) |index| {
                removeNodeAt(&row.excluded_once_nodes, index);
                self.log.aggregate_bytes -= @sizeOf(u64);
                self.log.checkpoint_body_bytes -= @sizeOf(u64);
            }
            result.rows_changed += 1;
            if (rowCovered(row.*)) {
                self.log.removeRowAt(row_index);
                result.rows_retired += 1;
            } else {
                row_index += 1;
            }
        }
        const cursor_index = lowerBoundCursors(self.log.cursors.items, self.node);
        if (cursor_index < self.log.cursors.items.len and
            self.log.cursors.items[cursor_index].node == self.node)
        {
            removeCursorSlot(&self.log.cursors, cursor_index);
            self.log.aggregate_bytes -= cursor_entry_len;
            self.log.checkpoint_body_bytes -= cursor_entry_len;
            result.cursor_removed = true;
        }
        self.log.prepared_active = false;
        self.log.bumpEpoch();
        self.state = .committed;
        return result;
    }

    pub fn abort(self: *PreparedNodeRetirement) void {
        if (self.state != .prepared) return;
        std.debug.assert(self.log.prepared_active);
        self.log.prepared_active = false;
        self.state = .aborted;
    }

    pub fn deinit(self: *PreparedNodeRetirement) void {
        if (self.state == .prepared) self.abort();
        self.* = undefined;
    }
};

pub const EventLog = struct {
    allocator: std.mem.Allocator,
    config: Config,
    frozen_config: Config,
    rows: std.ArrayListUnmanaged(Row) = .empty,
    cursors: std.ArrayListUnmanaged(CursorEntry) = .empty,
    aggregate_bytes: usize = 0,
    checkpoint_body_bytes: usize = 0,
    mutation_epoch: u64 = 0,
    prepared_active: bool = false,

    pub fn init(allocator: std.mem.Allocator, config: Config) error{InvalidConfig}!EventLog {
        if (!config.valid()) return error.InvalidConfig;
        return .{ .allocator = allocator, .config = config, .frozen_config = config };
    }

    pub fn deinit(self: *EventLog) void {
        for (self.rows.items) |*row| row.deinit(self.allocator);
        self.rows.deinit(self.allocator);
        self.cursors.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn len(self: *const EventLog) usize {
        return self.rows.items.len;
    }

    pub fn viewAt(self: *const EventLog, index: usize) RowView {
        const row = &self.rows.items[index];
        return .{
            .relay_id = row.relay_id,
            .origin_pubkey = row.origin_pubkey,
            .origin_node = row.origin_node,
            .hlc = row.hlc,
            .wire = row.wire,
            .required_nodes = row.required_nodes.items,
            .confirmed_nodes = row.confirmed_nodes.items,
            .excluded_once_nodes = row.excluded_once_nodes.items,
        };
    }

    pub fn contains(self: *const EventLog, relay_id: RelayId) bool {
        const index = lowerBoundRows(self.rows.items, relay_id);
        return index < self.rows.items.len and idsEqual(self.rows.items[index].relay_id, relay_id);
    }

    /// Return the retained row for `relay_id`, or null when this log has no
    /// such accepted-event authority. Every slice in the view aliases the log
    /// and remains valid only until the next mutation or `deinit`.
    pub fn viewFor(self: *const EventLog, relay_id: RelayId) ?RowView {
        const index = lowerBoundRows(self.rows.items, relay_id);
        if (index == self.rows.items.len or !idsEqual(self.rows.items[index].relay_id, relay_id))
            return null;
        return self.viewAt(index);
    }

    /// Return the exact canonical wire retained for `relay_id`, or null when
    /// this log has no such accepted-event authority. The slice aliases the
    /// log and remains valid only until the next mutation or `deinit`.
    pub fn wireFor(self: *const EventLog, relay_id: RelayId) ?[]const u8 {
        return if (self.viewFor(relay_id)) |row| row.wire else null;
    }

    pub fn isConfirmedBy(self: *const EventLog, relay_id: RelayId, node: u64) bool {
        const index = lowerBoundRows(self.rows.items, relay_id);
        if (index == self.rows.items.len or !idsEqual(self.rows.items[index].relay_id, relay_id))
            return false;
        return containsNode(self.rows.items[index].confirmed_nodes.items, node);
    }

    fn beginPrepare(self: *EventLog) Error!u64 {
        try self.validateLiveConfig();
        if (self.prepared_active) return error.PreparedMutationActive;
        self.prepared_active = true;
        return self.mutation_epoch;
    }

    fn bumpEpoch(self: *EventLog) void {
        self.mutation_epoch +%= 1;
    }

    fn validateLiveConfig(self: *const EventLog) Error!void {
        if (!self.config.valid()) return error.InvalidConfig;
        if (!Config.eql(self.config, self.frozen_config)) return error.ConfigMismatch;
        if (self.rows.items.len > self.config.max_rows or
            self.cursors.items.len > self.config.max_cursor_nodes)
            return error.CapacityExceeded;
    }

    /// Prepare exact accepted MESSAGE_V2 authority. `accepting_node` is the
    /// local node whose durable acceptance this commit publishes. `ingress_node`
    /// is merely a one-sweep loop exclusion and is never treated as a durable
    /// confirmation. `required_nodes` is the sorted authoritative membership
    /// snapshot for this event; later joins do not modify an existing row.
    pub fn prepareAccepted(
        self: *EventLog,
        relay_id: RelayId,
        wire: []const u8,
        accepting_node: u64,
        ingress_node: ?u64,
        required_nodes: []const u64,
    ) Error!PrepareAcceptedResult {
        if (accepting_node == 0) return error.InvalidNode;
        if (ingress_node) |node| if (node == 0) return error.InvalidNode;
        try validateRequiredMembership(required_nodes, accepting_node, self.config.max_confirmed_nodes_per_row);
        const expected_epoch = try self.beginPrepare();
        errdefer self.prepared_active = false;
        const index = lowerBoundRows(self.rows.items, relay_id);
        if (index < self.rows.items.len and idsEqual(self.rows.items[index].relay_id, relay_id)) {
            const row = &self.rows.items[index];
            if (!std.mem.eql(u8, row.wire, wire)) {
                self.prepared_active = false;
                return .conflict;
            }
            if (ingress_node) |node| {
                if (containsNode(row.required_nodes.items, node) and
                    !containsNode(row.confirmed_nodes.items, node) and
                    !containsNode(row.excluded_once_nodes.items, node))
                {
                    if (row.excluded_once_nodes.items.len >= self.config.max_confirmed_nodes_per_row)
                        return error.CapacityExceeded;
                    try self.ensureProspectiveCapacity(@sizeOf(u64), @sizeOf(u64));
                    const excluded_index = lowerBoundNodes(row.excluded_once_nodes.items, node);
                    try row.excluded_once_nodes.ensureUnusedCapacity(self.allocator, 1);
                    return .{ .ready = .{
                        .log = self,
                        .expected_epoch = expected_epoch,
                        .outcome_value = .exact_duplicate,
                        .action = .{ .add_exclusion = .{
                            .row_index = index,
                            .insert_index = excluded_index,
                            .node = node,
                        } },
                    } };
                }
            }
            return .{ .ready = .{
                .log = self,
                .expected_epoch = expected_epoch,
                .outcome_value = .exact_duplicate,
                .action = .no_op,
            } };
        }

        if (self.rows.items.len >= self.config.max_rows) return error.CapacityExceeded;
        const excluded_count: usize = if (ingress_node != null and
            ingress_node.? != accepting_node and
            containsNode(required_nodes, ingress_node.?)) 1 else 0;
        const added_aggregate = std.math.add(usize, wire.len, (required_nodes.len + 1 + excluded_count) * @sizeOf(u64)) catch
            return error.CapacityExceeded;
        const added_body = std.math.add(usize, row_prefix_len, added_aggregate) catch
            return error.CapacityExceeded;
        try self.ensureProspectiveCapacity(added_aggregate, added_body);
        const wire_meta = try validateWireAndId(self.allocator, self.config, relay_id, wire);
        if (self.hasOriginHlc(wire_meta.origin_pubkey, wire_meta.hlc))
            return error.DuplicateEntry;

        var staged = Row{
            .relay_id = relay_id,
            .origin_pubkey = wire_meta.origin_pubkey,
            .origin_node = wire_meta.origin_node,
            .hlc = wire_meta.hlc,
            .wire = try self.allocator.dupe(u8, wire),
        };
        errdefer staged.deinit(self.allocator);
        try staged.required_nodes.ensureTotalCapacity(self.allocator, required_nodes.len);
        staged.required_nodes.appendSliceAssumeCapacity(required_nodes);
        try staged.confirmed_nodes.ensureTotalCapacity(self.allocator, 1);
        staged.confirmed_nodes.appendAssumeCapacity(accepting_node);
        if (ingress_node) |node| if (node != accepting_node and containsNode(required_nodes, node)) {
            try staged.excluded_once_nodes.ensureTotalCapacity(self.allocator, 1);
            staged.excluded_once_nodes.appendAssumeCapacity(node);
        };
        try self.rows.ensureUnusedCapacity(self.allocator, 1);
        return .{ .ready = .{
            .log = self,
            .expected_epoch = expected_epoch,
            .outcome_value = .inserted,
            .action = .{ .insert = staged },
        } };
    }

    pub fn reserveAccepted(
        self: *EventLog,
        relay_id: RelayId,
        wire: []const u8,
        accepting_node: u64,
        ingress_node: ?u64,
        required_nodes: []const u64,
    ) Error!ReserveOutcome {
        var result = try self.prepareAccepted(relay_id, wire, accepting_node, ingress_node, required_nodes);
        return switch (result) {
            .conflict => .conflict,
            .ready => |*prepared| blk: {
                defer prepared.deinit();
                break :blk prepared.commit();
            },
        };
    }

    pub fn prepareAuthenticatedDurableAck(
        self: *EventLog,
        relay_id: RelayId,
        confirmed_node: u64,
    ) Error!PreparedConfirmation {
        if (confirmed_node == 0) return error.InvalidNode;
        const expected_epoch = try self.beginPrepare();
        errdefer self.prepared_active = false;
        const index = lowerBoundRows(self.rows.items, relay_id);
        if (index == self.rows.items.len or !idsEqual(self.rows.items[index].relay_id, relay_id))
            return error.NotFound;
        const row = &self.rows.items[index];
        if (!containsNode(row.required_nodes.items, confirmed_node)) return error.NodeNotRequired;
        if (containsNode(row.confirmed_nodes.items, confirmed_node)) return .{
            .log = self,
            .expected_epoch = expected_epoch,
            .outcome_value = .already_confirmed,
            .action = .no_op,
        };
        if (coverageAfterConfirmation(row.*, confirmed_node)) return .{
            .log = self,
            .expected_epoch = expected_epoch,
            .outcome_value = .confirmed_and_retired,
            .action = .{ .retire_row = index },
        };
        const excluded_index = nodeIndex(row.excluded_once_nodes.items, confirmed_node);
        if (excluded_index == null) try self.ensureProspectiveCapacity(@sizeOf(u64), @sizeOf(u64));
        const confirmed_index = lowerBoundNodes(row.confirmed_nodes.items, confirmed_node);
        try row.confirmed_nodes.ensureUnusedCapacity(self.allocator, 1);
        return .{
            .log = self,
            .expected_epoch = expected_epoch,
            .outcome_value = .confirmed,
            .action = .{ .add = .{
                .row_index = index,
                .confirmed_index = confirmed_index,
                .excluded_index = excluded_index,
                .node = confirmed_node,
            } },
        };
    }

    pub fn confirmAuthenticatedDurableAck(
        self: *EventLog,
        relay_id: RelayId,
        confirmed_node: u64,
    ) Error!ConfirmationOutcome {
        var prepared = try self.prepareAuthenticatedDurableAck(relay_id, confirmed_node);
        defer prepared.deinit();
        return prepared.commit();
    }

    pub fn prepareConfiguredNodeRetirement(self: *EventLog, node: u64) Error!PreparedNodeRetirement {
        if (node == 0) return error.InvalidNode;
        const expected_epoch = try self.beginPrepare();
        return .{ .log = self, .expected_epoch = expected_epoch, .node = node };
    }

    fn hasOriginHlc(
        self: *const EventLog,
        origin_pubkey: [message_relay_v2.pubkey_len]u8,
        hlc: u64,
    ) bool {
        for (self.rows.items) |row| {
            if (row.hlc == hlc and std.mem.eql(u8, &row.origin_pubkey, &origin_pubkey))
                return true;
        }
        return false;
    }

    /// Fill `out` with exact wires required by `target_node` and not durably
    /// confirmed there. At most the lowest missing HLC for each origin is
    /// exposed: a higher event can never overtake a lower unconfirmed event and
    /// be retired by RVG2's greatest-W watermark. The durable per-target cursor
    /// rotates origins for fairness; it never advances within an origin. Ingress
    /// exclusion consumes one head sweep, then the same head becomes eligible.
    pub fn collectPageForNode(
        self: *EventLog,
        target_node: u64,
        out: []PageItem,
    ) Error!usize {
        if (target_node == 0) return error.InvalidNode;
        try self.validateLiveConfig();
        if (self.prepared_active) return error.PreparedMutationActive;
        if (self.rows.items.len == 0 or out.len == 0) return 0;
        var has_missing = false;
        for (self.rows.items) |row| if (rowMissingForTarget(row, target_node)) {
            has_missing = true;
            break;
        };
        if (!has_missing) return 0;

        var cursor_index = lowerBoundCursors(self.cursors.items, target_node);
        if (cursor_index == self.cursors.items.len or self.cursors.items[cursor_index].node != target_node) {
            if (self.cursors.items.len >= self.config.max_cursor_nodes) return error.CapacityExceeded;
            try self.ensureProspectiveCapacity(cursor_entry_len, cursor_entry_len);
            try self.cursors.ensureUnusedCapacity(self.allocator, 1);
            insertCursorAssumeCapacity(&self.cursors, cursor_index, .{
                .node = target_node,
                // Starting after the greatest origin wraps the first page to
                // the canonical minimum while keeping the cursor referentially
                // strict in checkpoints.
                .after_origin_pubkey = greatestMissingOrigin(self.rows.items, target_node).?,
            });
            self.aggregate_bytes += cursor_entry_len;
            self.checkpoint_body_bytes += cursor_entry_len;
            self.bumpEpoch();
        }
        cursor_index = lowerBoundCursors(self.cursors.items, target_node);
        const wrap_at = self.cursors.items[cursor_index].after_origin_pubkey;
        var after: ?[message_relay_v2.pubkey_len]u8 = wrap_at;
        var upper: ?[message_relay_v2.pubkey_len]u8 = null;
        var wrapped = false;
        var written: usize = 0;
        while (written < out.len) {
            const head_index = nextOriginHead(self.rows.items, target_node, after, upper) orelse {
                if (wrapped) break;
                wrapped = true;
                after = null;
                upper = wrap_at;
                continue;
            };
            const row = &self.rows.items[head_index];
            after = row.origin_pubkey;
            if (!std.mem.eql(
                u8,
                &self.cursors.items[cursor_index].after_origin_pubkey,
                &row.origin_pubkey,
            )) {
                self.cursors.items[cursor_index].after_origin_pubkey = row.origin_pubkey;
                self.bumpEpoch();
            }
            if (nodeIndex(row.excluded_once_nodes.items, target_node)) |excluded_index| {
                removeNodeAt(&row.excluded_once_nodes, excluded_index);
                self.aggregate_bytes -= @sizeOf(u64);
                self.checkpoint_body_bytes -= @sizeOf(u64);
                self.bumpEpoch();
                continue;
            }
            out[written] = .{
                .relay_id = row.relay_id,
                .origin_pubkey = row.origin_pubkey,
                .origin_node = row.origin_node,
                .hlc = row.hlc,
                .wire = row.wire,
            };
            written += 1;
        }
        return written;
    }

    fn ensureProspectiveCapacity(
        self: *const EventLog,
        added_aggregate: usize,
        added_body: usize,
    ) Error!void {
        const aggregate = std.math.add(usize, self.aggregate_bytes, added_aggregate) catch
            return error.CapacityExceeded;
        if (aggregate > self.config.max_aggregate_bytes) return error.CapacityExceeded;
        const body = std.math.add(usize, self.checkpoint_body_bytes, added_body) catch
            return error.CapacityExceeded;
        if (body > hard_max_checkpoint_bytes - checkpoint_header_len - checksum_len)
            return error.CapacityExceeded;
    }

    fn removeRowAt(self: *EventLog, index: usize) void {
        const removed_origin = self.rows.items[index].origin_pubkey;
        const aggregate = rowAggregateBytes(self.rows.items[index]);
        const body = rowBodyBytes(self.rows.items[index]);
        self.rows.items[index].deinit(self.allocator);
        removeRowSlot(&self.rows, index);
        self.aggregate_bytes -= aggregate;
        self.checkpoint_body_bytes -= body;
        if (self.rows.items.len == 0) {
            const cursor_bytes = self.cursors.items.len * cursor_entry_len;
            self.cursors.clearRetainingCapacity();
            self.aggregate_bytes -= cursor_bytes;
            self.checkpoint_body_bytes -= cursor_bytes;
            return;
        }
        if (!containsOrigin(self.rows.items, removed_origin)) {
            const fallback = greatestOrigin(self.rows.items).?;
            for (self.cursors.items) |*cursor| {
                if (std.mem.eql(u8, &cursor.after_origin_pubkey, &removed_origin))
                    cursor.after_origin_pubkey = fallback;
            }
        }
    }

    pub fn encodeCheckpoint(self: *const EventLog, allocator: std.mem.Allocator) Error![]u8 {
        try self.validateLiveConfig();
        if (self.prepared_active) return error.PreparedMutationActive;
        var body_len: usize = 0;
        var aggregate: usize = 0;
        var previous_id: ?RelayId = null;
        for (self.rows.items) |row| {
            if (row.wire.len == 0 or row.wire.len > self.config.max_wire_bytes)
                return error.InvalidWire;
            if (row.required_nodes.items.len == 0 or
                row.required_nodes.items.len > self.config.max_confirmed_nodes_per_row or
                row.confirmed_nodes.items.len > row.required_nodes.items.len or
                row.excluded_once_nodes.items.len > self.config.max_confirmed_nodes_per_row)
                return error.CapacityExceeded;
            if (previous_id) |previous| {
                if (idsEqual(previous, row.relay_id)) return error.DuplicateEntry;
                if (!idLess(previous, row.relay_id)) return error.NonCanonicalOrder;
            }
            previous_id = row.relay_id;
            try validateRowNodes(row);
            const node_count = row.required_nodes.items.len + row.confirmed_nodes.items.len + row.excluded_once_nodes.items.len;
            const nodes_bytes = std.math.mul(usize, node_count, @sizeOf(u64)) catch
                return error.CheckpointTooLarge;
            aggregate = std.math.add(usize, aggregate, row.wire.len + nodes_bytes) catch
                return error.CheckpointTooLarge;
            body_len = std.math.add(usize, body_len, row_prefix_len + row.wire.len + nodes_bytes) catch
                return error.CheckpointTooLarge;
        }
        if (self.rows.items.len > self.config.max_rows or
            self.cursors.items.len > self.config.max_cursor_nodes)
            return error.CapacityExceeded;
        var previous_cursor_node: ?u64 = null;
        for (self.cursors.items) |cursor| {
            if (cursor.node == 0) return error.InvalidNode;
            if (previous_cursor_node) |previous| {
                if (cursor.node == previous) return error.DuplicateNode;
                if (cursor.node < previous) return error.NonCanonicalOrder;
            }
            if (!containsOrigin(self.rows.items, cursor.after_origin_pubkey))
                return error.CursorTargetMissing;
            previous_cursor_node = cursor.node;
            aggregate = std.math.add(usize, aggregate, cursor_entry_len) catch return error.CheckpointTooLarge;
            body_len = std.math.add(usize, body_len, cursor_entry_len) catch return error.CheckpointTooLarge;
        }
        if (aggregate > self.config.max_aggregate_bytes) return error.CapacityExceeded;
        if (aggregate != self.aggregate_bytes or body_len != self.checkpoint_body_bytes)
            return error.CounterMismatch;
        const prefix_len = std.math.add(usize, checkpoint_header_len, body_len) catch
            return error.CheckpointTooLarge;
        const total_len = std.math.add(usize, prefix_len, checksum_len) catch
            return error.CheckpointTooLarge;
        if (total_len > hard_max_checkpoint_bytes or body_len > std.math.maxInt(u64))
            return error.CheckpointTooLarge;

        const out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);
        @memcpy(out[0..magic.len], &magic);
        out[4] = checkpoint_version;
        out[5] = 0;
        writeU32(out[6..10], @intCast(self.config.max_rows));
        writeU32(out[10..14], @intCast(self.config.max_confirmed_nodes_per_row));
        writeU32(out[14..18], @intCast(self.config.max_wire_bytes));
        writeU64(out[18..26], @intCast(self.config.max_aggregate_bytes));
        writeU32(out[26..30], @intCast(self.config.max_cursor_nodes));
        writeU32(out[30..34], @intCast(self.rows.items.len));
        writeU32(out[34..38], @intCast(self.cursors.items.len));
        writeU64(out[38..46], @intCast(body_len));
        var pos: usize = checkpoint_header_len;
        for (self.rows.items) |row| {
            @memcpy(out[pos..][0..@sizeOf(RelayId)], &row.relay_id);
            pos += @sizeOf(RelayId);
            @memcpy(out[pos..][0..message_relay_v2.pubkey_len], &row.origin_pubkey);
            pos += message_relay_v2.pubkey_len;
            writeU64(out[pos..][0..8], row.origin_node);
            pos += 8;
            writeU64(out[pos..][0..8], row.hlc);
            pos += 8;
            writeU32(out[pos..][0..4], @intCast(row.wire.len));
            pos += 4;
            writeU32(out[pos..][0..4], @intCast(row.confirmed_nodes.items.len));
            pos += 4;
            writeU32(out[pos..][0..4], @intCast(row.required_nodes.items.len));
            pos += 4;
            writeU32(out[pos..][0..4], @intCast(row.excluded_once_nodes.items.len));
            pos += 4;
            @memcpy(out[pos..][0..row.wire.len], row.wire);
            pos += row.wire.len;
            for (row.required_nodes.items) |node| {
                writeU64(out[pos..][0..8], node);
                pos += 8;
            }
            for (row.confirmed_nodes.items) |node| {
                writeU64(out[pos..][0..8], node);
                pos += 8;
            }
            for (row.excluded_once_nodes.items) |node| {
                writeU64(out[pos..][0..8], node);
                pos += 8;
            }
        }
        for (self.cursors.items) |cursor| {
            writeU64(out[pos..][0..8], cursor.node);
            pos += 8;
            @memcpy(out[pos..][0..message_relay_v2.pubkey_len], &cursor.after_origin_pubkey);
            pos += message_relay_v2.pubkey_len;
        }
        std.debug.assert(pos == prefix_len);
        checkpointChecksum(out[0..prefix_len], out[prefix_len..][0..checksum_len]);
        return out;
    }

    /// Strict-current transactional restore. The returned log is fully staged;
    /// callers may swap it into Helix state only after every sibling capsule
    /// has also validated. No legacy fallback belongs on this path.
    pub fn decodeCheckpoint(
        allocator: std.mem.Allocator,
        expected_config: Config,
        bytes: []const u8,
    ) Error!EventLog {
        const meta = try validateCheckpoint(bytes);
        if (!Config.eql(meta.config, expected_config)) return error.ConfigMismatch;
        var out = try EventLog.init(allocator, expected_config);
        errdefer out.deinit();
        try out.rows.ensureTotalCapacity(allocator, meta.row_count);
        var pos: usize = checkpoint_header_len;
        for (0..meta.row_count) |_| {
            const relay_id: RelayId = bytes[pos..][0..@sizeOf(RelayId)].*;
            pos += @sizeOf(RelayId);
            const origin_pubkey: [message_relay_v2.pubkey_len]u8 = bytes[pos..][0..message_relay_v2.pubkey_len].*;
            pos += message_relay_v2.pubkey_len;
            const origin_node = readU64(bytes[pos..][0..8]);
            pos += 8;
            const hlc = readU64(bytes[pos..][0..8]);
            pos += 8;
            const wire_len: usize = readU32(bytes[pos..][0..4]);
            pos += 4;
            const node_count: usize = readU32(bytes[pos..][0..4]);
            pos += 4;
            const required_count: usize = readU32(bytes[pos..][0..4]);
            pos += 4;
            const excluded_count: usize = readU32(bytes[pos..][0..4]);
            pos += 4;
            const row = try decodeRow(
                allocator,
                expected_config,
                relay_id,
                origin_pubkey,
                origin_node,
                hlc,
                bytes[pos..][0..wire_len],
                bytes[pos + wire_len ..],
                required_count,
                node_count,
                excluded_count,
            );
            pos += wire_len + (required_count + node_count + excluded_count) * @sizeOf(u64);
            for (out.rows.items) |existing| {
                if (existing.hlc == row.hlc and originEqual(existing.origin_pubkey, row.origin_pubkey)) {
                    var invalid = row;
                    invalid.deinit(allocator);
                    return error.DuplicateEntry;
                }
            }
            out.rows.appendAssumeCapacity(row);
        }
        try out.cursors.ensureTotalCapacity(allocator, meta.cursor_count);
        for (0..meta.cursor_count) |_| {
            const node = readU64(bytes[pos..][0..8]);
            pos += 8;
            const after_origin_pubkey: [message_relay_v2.pubkey_len]u8 = bytes[pos..][0..message_relay_v2.pubkey_len].*;
            pos += message_relay_v2.pubkey_len;
            if (!containsOrigin(out.rows.items, after_origin_pubkey))
                return error.CursorTargetMissing;
            out.cursors.appendAssumeCapacity(.{ .node = node, .after_origin_pubkey = after_origin_pubkey });
        }
        out.aggregate_bytes = meta.aggregate_bytes;
        out.checkpoint_body_bytes = meta.body_len;
        if (recomputeAggregateBytes(out.rows.items, out.cursors.items) != out.aggregate_bytes or
            recomputeBodyBytes(out.rows.items, out.cursors.items) != out.checkpoint_body_bytes)
            return error.CounterMismatch;
        return out;
    }
};

pub const CheckpointMeta = struct {
    config: Config,
    row_count: usize,
    cursor_count: usize,
    body_len: usize,
    aggregate_bytes: usize,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], &magic);
}

/// Allocation-free structural validation. Cryptographic wire and derived-id
/// validation is completed by `EventLog.decodeCheckpoint` before publication.
pub fn validateCheckpoint(bytes: []const u8) Error!CheckpointMeta {
    if (bytes.len < checkpoint_header_len + checksum_len) return error.Truncated;
    if (!isCheckpoint(bytes)) return error.BadMagic;
    if (bytes[4] != checkpoint_version) return error.UnsupportedVersion;
    if (bytes[5] != 0) return error.UnknownFlags;
    const config = Config{
        .max_rows = readU32(bytes[6..10]),
        .max_confirmed_nodes_per_row = readU32(bytes[10..14]),
        .max_wire_bytes = readU32(bytes[14..18]),
        .max_aggregate_bytes = std.math.cast(usize, readU64(bytes[18..26])) orelse
            return error.InvalidConfig,
        .max_cursor_nodes = readU32(bytes[26..30]),
    };
    if (!config.valid()) return error.InvalidConfig;
    const row_count: usize = readU32(bytes[30..34]);
    const cursor_count: usize = readU32(bytes[34..38]);
    const body_len = std.math.cast(usize, readU64(bytes[38..46])) orelse
        return error.CheckpointTooLarge;
    if (row_count > config.max_rows) return error.CapacityExceeded;
    if (cursor_count > config.max_cursor_nodes) return error.CapacityExceeded;
    if (row_count == 0 and cursor_count != 0) return error.InvalidState;
    const prefix_len = std.math.add(usize, checkpoint_header_len, body_len) catch
        return error.CheckpointTooLarge;
    const total_len = std.math.add(usize, prefix_len, checksum_len) catch
        return error.CheckpointTooLarge;
    if (total_len > hard_max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < total_len) return error.Truncated;
    if (bytes.len > total_len) return error.TrailingBytes;
    var actual_checksum: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0..prefix_len], &actual_checksum);
    if (!std.mem.eql(u8, &actual_checksum, bytes[prefix_len..])) return error.ChecksumMismatch;

    var pos: usize = checkpoint_header_len;
    var previous_id: ?RelayId = null;
    var aggregate: usize = 0;
    for (0..row_count) |_| {
        if (pos > prefix_len or prefix_len - pos < row_prefix_len) return error.Truncated;
        const relay_id: RelayId = bytes[pos..][0..@sizeOf(RelayId)].*;
        pos += @sizeOf(RelayId);
        if (previous_id) |previous| {
            if (idsEqual(previous, relay_id)) return error.DuplicateEntry;
            if (!idLess(previous, relay_id)) return error.NonCanonicalOrder;
        }
        previous_id = relay_id;
        pos += message_relay_v2.pubkey_len;
        const origin_node = readU64(bytes[pos..][0..8]);
        pos += 8;
        if (origin_node == 0) return error.InvalidNode;
        pos += 8; // HLC; canonical MESSAGE_V2 semantics are checked on decode.
        const wire_len: usize = readU32(bytes[pos..][0..4]);
        pos += 4;
        const node_count: usize = readU32(bytes[pos..][0..4]);
        pos += 4;
        const required_count: usize = readU32(bytes[pos..][0..4]);
        pos += 4;
        const excluded_count: usize = readU32(bytes[pos..][0..4]);
        pos += 4;
        if (wire_len == 0 or wire_len > config.max_wire_bytes) return error.InvalidWire;
        if (required_count == 0 or required_count > config.max_confirmed_nodes_per_row or
            node_count > required_count or excluded_count > config.max_confirmed_nodes_per_row)
            return error.CapacityExceeded;
        const total_node_count = std.math.add(usize, required_count, node_count) catch
            return error.CheckpointTooLarge;
        const all_node_count = std.math.add(usize, total_node_count, excluded_count) catch
            return error.CheckpointTooLarge;
        const nodes_bytes = std.math.mul(usize, all_node_count, @sizeOf(u64)) catch
            return error.CheckpointTooLarge;
        const row_bytes = std.math.add(usize, wire_len, nodes_bytes) catch
            return error.CheckpointTooLarge;
        if (pos > prefix_len or row_bytes > prefix_len - pos) return error.Truncated;
        aggregate = std.math.add(usize, aggregate, row_bytes) catch
            return error.CheckpointTooLarge;
        if (aggregate > config.max_aggregate_bytes) return error.CapacityExceeded;
        pos += wire_len;
        const required_bytes = bytes[pos..][0 .. required_count * @sizeOf(u64)];
        pos += required_bytes.len;
        const confirmed_bytes = bytes[pos..][0 .. node_count * @sizeOf(u64)];
        pos += confirmed_bytes.len;
        const excluded_bytes = bytes[pos..][0 .. excluded_count * @sizeOf(u64)];
        pos += excluded_bytes.len;
        try validateEncodedNodeOrder(required_bytes, required_count);
        try validateEncodedNodeOrder(confirmed_bytes, node_count);
        try validateEncodedNodeOrder(excluded_bytes, excluded_count);
        if (!encodedSubset(confirmed_bytes, node_count, required_bytes, required_count) or
            !encodedSubset(excluded_bytes, excluded_count, required_bytes, required_count) or
            !encodedDisjoint(confirmed_bytes, node_count, excluded_bytes, excluded_count))
            return error.InvalidMembership;
        if (node_count == required_count) return error.InvalidState;
    }
    var previous_cursor_node: ?u64 = null;
    for (0..cursor_count) |_| {
        if (pos > prefix_len or prefix_len - pos < cursor_entry_len) return error.Truncated;
        const node = readU64(bytes[pos..][0..8]);
        pos += 8;
        pos += message_relay_v2.pubkey_len;
        if (node == 0) return error.InvalidNode;
        if (previous_cursor_node) |previous| {
            if (node == previous) return error.DuplicateNode;
            if (node < previous) return error.NonCanonicalOrder;
        }
        previous_cursor_node = node;
        aggregate = std.math.add(usize, aggregate, cursor_entry_len) catch
            return error.CheckpointTooLarge;
        if (aggregate > config.max_aggregate_bytes) return error.CapacityExceeded;
    }
    if (pos < prefix_len) return error.TrailingBytes;
    if (pos > prefix_len) return error.Truncated;
    return .{
        .config = config,
        .row_count = row_count,
        .cursor_count = cursor_count,
        .body_len = body_len,
        .aggregate_bytes = aggregate,
    };
}

fn decodeRow(
    allocator: std.mem.Allocator,
    config: Config,
    relay_id: RelayId,
    origin_pubkey: [message_relay_v2.pubkey_len]u8,
    origin_node: u64,
    hlc: u64,
    wire_bytes: []const u8,
    node_bytes: []const u8,
    required_count: usize,
    node_count: usize,
    excluded_count: usize,
) Error!Row {
    const wire_meta = try validateWireAndId(allocator, config, relay_id, wire_bytes);
    if (!originEqual(origin_pubkey, wire_meta.origin_pubkey) or
        origin_node != wire_meta.origin_node or hlc != wire_meta.hlc)
        return error.InvalidWire;
    var row = Row{
        .relay_id = relay_id,
        .origin_pubkey = origin_pubkey,
        .origin_node = origin_node,
        .hlc = hlc,
        .wire = try allocator.dupe(u8, wire_bytes),
    };
    errdefer row.deinit(allocator);
    var offset: usize = 0;
    try row.required_nodes.ensureTotalCapacity(allocator, required_count);
    for (0..required_count) |_| {
        row.required_nodes.appendAssumeCapacity(readU64(node_bytes[offset..][0..8]));
        offset += @sizeOf(u64);
    }
    try row.confirmed_nodes.ensureTotalCapacity(allocator, node_count);
    for (0..node_count) |_| {
        row.confirmed_nodes.appendAssumeCapacity(readU64(node_bytes[offset..][0..8]));
        offset += @sizeOf(u64);
    }
    try row.excluded_once_nodes.ensureTotalCapacity(allocator, excluded_count);
    for (0..excluded_count) |_| {
        row.excluded_once_nodes.appendAssumeCapacity(readU64(node_bytes[offset..][0..8]));
        offset += @sizeOf(u64);
    }
    return row;
}

const WireMeta = struct {
    origin_pubkey: [message_relay_v2.pubkey_len]u8,
    origin_node: u64,
    hlc: u64,
};

fn validateWireAndId(
    allocator: std.mem.Allocator,
    config: Config,
    expected_id: RelayId,
    wire: []const u8,
) Error!WireMeta {
    if (wire.len == 0 or wire.len > config.max_wire_bytes) return error.InvalidWire;
    var owned = message_relay_v2.decode(allocator, wire) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidWire,
    };
    defer owned.deinit(allocator);
    const derived = switch (try message_relay_v2.verifyAndRelayId(allocator, owned.msg)) {
        .verified => |id| id,
        else => return error.InvalidWire,
    };
    if (!idsEqual(derived, expected_id)) return error.RelayIdMismatch;
    const canonical = message_relay_v2.encode(allocator, owned.msg) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidWire,
    };
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, wire)) return error.InvalidWire;
    return .{
        .origin_pubkey = owned.msg.origin_pubkey[0..message_relay_v2.pubkey_len].*,
        .origin_node = owned.msg.origin_node,
        .hlc = owned.msg.hlc,
    };
}

fn validateNodeOrder(nodes: []const u64) Error!void {
    var previous: ?u64 = null;
    for (nodes) |node| {
        if (node == 0) return error.InvalidNode;
        if (previous) |prior| {
            if (node == prior) return error.DuplicateNode;
            if (node < prior) return error.NonCanonicalOrder;
        }
        previous = node;
    }
}

fn validateRequiredMembership(nodes: []const u64, accepting_node: u64, maximum: usize) Error!void {
    if (nodes.len < 2 or nodes.len > maximum) return error.InvalidMembership;
    try validateNodeOrder(nodes);
    if (!containsNode(nodes, accepting_node)) return error.InvalidMembership;
}

fn validateRowNodes(row: Row) Error!void {
    try validateNodeOrder(row.required_nodes.items);
    try validateNodeOrder(row.confirmed_nodes.items);
    try validateNodeOrder(row.excluded_once_nodes.items);
    for (row.confirmed_nodes.items) |node| {
        if (!containsNode(row.required_nodes.items, node) or
            containsNode(row.excluded_once_nodes.items, node))
            return error.InvalidMembership;
    }
    for (row.excluded_once_nodes.items) |node|
        if (!containsNode(row.required_nodes.items, node)) return error.InvalidMembership;
    if (rowCovered(row)) return error.InvalidState;
}

fn rowCovered(row: Row) bool {
    return row.confirmed_nodes.items.len == row.required_nodes.items.len;
}

fn coverageAfterConfirmation(row: Row, node: u64) bool {
    std.debug.assert(containsNode(row.required_nodes.items, node));
    std.debug.assert(!containsNode(row.confirmed_nodes.items, node));
    return row.confirmed_nodes.items.len + 1 == row.required_nodes.items.len;
}

fn rowAggregateBytes(row: Row) usize {
    return row.wire.len +
        (row.required_nodes.items.len + row.confirmed_nodes.items.len + row.excluded_once_nodes.items.len) * @sizeOf(u64);
}

fn rowBodyBytes(row: Row) usize {
    return row_prefix_len + rowAggregateBytes(row);
}

fn recomputeAggregateBytes(rows: []const Row, cursors: []const CursorEntry) usize {
    var total = cursors.len * cursor_entry_len;
    for (rows) |row| total += rowAggregateBytes(row);
    return total;
}

fn recomputeBodyBytes(rows: []const Row, cursors: []const CursorEntry) usize {
    var total = cursors.len * cursor_entry_len;
    for (rows) |row| total += rowBodyBytes(row);
    return total;
}

fn validateEncodedNodeOrder(bytes: []const u8, count: usize) Error!void {
    var previous: ?u64 = null;
    for (0..count) |index| {
        const node = readU64(bytes[index * 8 ..][0..8]);
        if (node == 0) return error.InvalidNode;
        if (previous) |prior| {
            if (node == prior) return error.DuplicateNode;
            if (node < prior) return error.NonCanonicalOrder;
        }
        previous = node;
    }
}

fn encodedSubset(
    subset: []const u8,
    subset_count: usize,
    superset: []const u8,
    superset_count: usize,
) bool {
    var sub_index: usize = 0;
    var super_index: usize = 0;
    while (sub_index < subset_count and super_index < superset_count) {
        const sub = readU64(subset[sub_index * 8 ..][0..8]);
        const super = readU64(superset[super_index * 8 ..][0..8]);
        if (super < sub) {
            super_index += 1;
        } else if (super == sub) {
            sub_index += 1;
            super_index += 1;
        } else return false;
    }
    return sub_index == subset_count;
}

fn encodedDisjoint(
    a: []const u8,
    a_count: usize,
    b: []const u8,
    b_count: usize,
) bool {
    var a_index: usize = 0;
    var b_index: usize = 0;
    while (a_index < a_count and b_index < b_count) {
        const av = readU64(a[a_index * 8 ..][0..8]);
        const bv = readU64(b[b_index * 8 ..][0..8]);
        if (av < bv) a_index += 1 else if (bv < av) b_index += 1 else return false;
    }
    return true;
}

fn rowMissingForTarget(row: Row, target_node: u64) bool {
    return containsNode(row.required_nodes.items, target_node) and
        !containsNode(row.confirmed_nodes.items, target_node);
}

fn pubkeyLess(
    a: [message_relay_v2.pubkey_len]u8,
    b: [message_relay_v2.pubkey_len]u8,
) bool {
    return std.mem.lessThan(u8, &a, &b);
}

fn originEqual(
    a: [message_relay_v2.pubkey_len]u8,
    b: [message_relay_v2.pubkey_len]u8,
) bool {
    return std.mem.eql(u8, &a, &b);
}

fn headLess(a: Row, b: Row) bool {
    return a.hlc < b.hlc or
        (a.hlc == b.hlc and idLess(a.relay_id, b.relay_id));
}

/// Select the lowest-HLC missing row for the lexicographically first origin in
/// `(after, upper]`. A null bound is open-ended. Repeated calls walk distinct
/// origins, never multiple rows from one origin in the same page.
fn nextOriginHead(
    rows: []const Row,
    target_node: u64,
    after: ?[message_relay_v2.pubkey_len]u8,
    upper: ?[message_relay_v2.pubkey_len]u8,
) ?usize {
    var best: ?usize = null;
    for (rows, 0..) |row, index| {
        if (!rowMissingForTarget(row, target_node)) continue;
        if (after) |lower| if (!pubkeyLess(lower, row.origin_pubkey)) continue;
        if (upper) |limit| if (pubkeyLess(limit, row.origin_pubkey)) continue;
        if (best) |best_index| {
            const selected = rows[best_index];
            if (pubkeyLess(row.origin_pubkey, selected.origin_pubkey) or
                (originEqual(row.origin_pubkey, selected.origin_pubkey) and headLess(row, selected)))
            {
                best = index;
            }
        } else {
            best = index;
        }
    }
    return best;
}

fn greatestMissingOrigin(
    rows: []const Row,
    target_node: u64,
) ?[message_relay_v2.pubkey_len]u8 {
    var greatest: ?[message_relay_v2.pubkey_len]u8 = null;
    for (rows) |row| {
        if (!rowMissingForTarget(row, target_node)) continue;
        if (greatest == null or pubkeyLess(greatest.?, row.origin_pubkey))
            greatest = row.origin_pubkey;
    }
    return greatest;
}

fn greatestOrigin(rows: []const Row) ?[message_relay_v2.pubkey_len]u8 {
    var greatest: ?[message_relay_v2.pubkey_len]u8 = null;
    for (rows) |row| {
        if (greatest == null or pubkeyLess(greatest.?, row.origin_pubkey))
            greatest = row.origin_pubkey;
    }
    return greatest;
}

fn containsOrigin(
    rows: []const Row,
    origin_pubkey: [message_relay_v2.pubkey_len]u8,
) bool {
    for (rows) |row| if (originEqual(row.origin_pubkey, origin_pubkey)) return true;
    return false;
}

fn idsEqual(a: RelayId, b: RelayId) bool {
    return std.mem.eql(u8, &a, &b);
}

fn idLess(a: RelayId, b: RelayId) bool {
    return std.mem.lessThan(u8, &a, &b);
}

fn lowerBoundRows(rows: []const Row, relay_id: RelayId) usize {
    var lo: usize = 0;
    var hi = rows.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (idLess(rows[mid].relay_id, relay_id))
            lo = mid + 1
        else
            hi = mid;
    }
    return lo;
}

fn lowerBoundNodes(nodes: []const u64, node: u64) usize {
    var lo: usize = 0;
    var hi = nodes.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (nodes[mid] < node)
            lo = mid + 1
        else
            hi = mid;
    }
    return lo;
}

fn lowerBoundCursors(cursors: []const CursorEntry, node: u64) usize {
    var lo: usize = 0;
    var hi = cursors.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (cursors[mid].node < node) lo = mid + 1 else hi = mid;
    }
    return lo;
}

fn containsNode(nodes: []const u64, node: u64) bool {
    const index = lowerBoundNodes(nodes, node);
    return index < nodes.len and nodes[index] == node;
}

fn nodeIndex(nodes: []const u64, node: u64) ?usize {
    const index = lowerBoundNodes(nodes, node);
    return if (index < nodes.len and nodes[index] == node) index else null;
}

fn insertNodeAssumeCapacity(nodes: *std.ArrayListUnmanaged(u64), index: usize, node: u64) void {
    const old_len = nodes.items.len;
    nodes.appendAssumeCapacity(undefined);
    var cursor = old_len;
    while (cursor > index) : (cursor -= 1) nodes.items[cursor] = nodes.items[cursor - 1];
    nodes.items[index] = node;
}

fn insertCursorAssumeCapacity(cursors: *std.ArrayListUnmanaged(CursorEntry), index: usize, entry: CursorEntry) void {
    const old_len = cursors.items.len;
    cursors.appendAssumeCapacity(undefined);
    var cursor = old_len;
    while (cursor > index) : (cursor -= 1) cursors.items[cursor] = cursors.items[cursor - 1];
    cursors.items[index] = entry;
}

fn removeNodeAt(nodes: *std.ArrayListUnmanaged(u64), index: usize) void {
    var cursor = index;
    while (cursor + 1 < nodes.items.len) : (cursor += 1) nodes.items[cursor] = nodes.items[cursor + 1];
    nodes.items.len -= 1;
}

fn removeRowSlot(rows: *std.ArrayListUnmanaged(Row), index: usize) void {
    var cursor = index;
    while (cursor + 1 < rows.items.len) : (cursor += 1) rows.items[cursor] = rows.items[cursor + 1];
    rows.items.len -= 1;
}

fn removeCursorSlot(cursors: *std.ArrayListUnmanaged(CursorEntry), index: usize) void {
    var cursor = index;
    while (cursor + 1 < cursors.items.len) : (cursor += 1) cursors.items[cursor] = cursors.items[cursor + 1];
    cursors.items.len -= 1;
}

const magic = [_]u8{ 'R', 'V', 'L', '2' };
const checkpoint_version: u8 = 3;
const checkpoint_header_len: usize = 46;
const row_origin_pubkey_offset: usize = @sizeOf(RelayId);
const row_origin_node_offset: usize = row_origin_pubkey_offset + message_relay_v2.pubkey_len;
const row_hlc_offset: usize = row_origin_node_offset + 8;
const row_wire_len_offset: usize = row_hlc_offset + 8;
const row_confirmed_count_offset: usize = row_wire_len_offset + 4;
const row_required_count_offset: usize = row_confirmed_count_offset + 4;
const row_excluded_count_offset: usize = row_required_count_offset + 4;
const row_prefix_len: usize = @sizeOf(RelayId) + message_relay_v2.pubkey_len + 8 + 8 + 4 + 4 + 4 + 4;
const cursor_entry_len: usize = @sizeOf(u64) + message_relay_v2.pubkey_len;
const checksum_len: usize = std.crypto.hash.Blake3.digest_length;
const checkpoint_checksum_domain = "onyx-relay-v2-event-log-checkpoint-v3";

fn checkpointChecksum(prefix: []const u8, out: *[checksum_len]u8) void {
    var h = std.crypto.hash.Blake3.init(.{});
    h.update(checkpoint_checksum_domain);
    h.update(prefix);
    h.final(out);
}

fn readU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .big);
}

fn readU64(bytes: *const [8]u8) u64 {
    return std.mem.readInt(u64, bytes, .big);
}

fn writeU32(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .big);
}

fn writeU64(bytes: *[8]u8, value: u64) void {
    std.mem.writeInt(u64, bytes, value, .big);
}

const testing = std.testing;

const TestWire = struct {
    id: RelayId,
    bytes: []u8,

    fn deinit(self: *TestWire, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

fn makeTestWire(
    allocator: std.mem.Allocator,
    kp: *const @import("../crypto/sign.zig").KeyPair,
    hlc: u64,
    text: []const u8,
) !TestWire {
    const signed_frame = @import("../substrate/undertow/signed_frame.zig");
    var pubkey: [message_relay_v2.pubkey_len]u8 = undefined;
    var signature: [message_relay_v2.sig_len]u8 = undefined;
    var msg = message_relay_v2.RelayMessage{
        .verb = .privmsg,
        .target = "#event-log",
        .source_prefix = "alice!u@mesh.test",
        .text = text,
        .scope_kind = .channel,
        .origin_node = signed_frame.originShortId(kp.public_key),
        .hlc = hlc,
    };
    try message_relay_v2.stampOrigin(allocator, &msg, kp, &pubkey, &signature);
    const id = switch (try message_relay_v2.verifyAndRelayId(allocator, msg)) {
        .verified => |verified| verified,
        else => return error.TestUnexpectedResult,
    };
    return .{ .id = id, .bytes = try message_relay_v2.encode(allocator, msg) };
}

fn takeReady(result: PrepareAcceptedResult) !PreparedAccepted {
    return switch (result) {
        .ready => |prepared| prepared,
        .conflict => error.TestUnexpectedResult,
    };
}

fn rowsEndInCheckpoint(bytes: []const u8) usize {
    var pos: usize = checkpoint_header_len;
    const row_count: usize = readU32(bytes[30..34]);
    for (0..row_count) |_| {
        const wire_len: usize = readU32(bytes[pos + row_wire_len_offset ..][0..4]);
        const confirmed_count: usize = readU32(bytes[pos + row_confirmed_count_offset ..][0..4]);
        const required_count: usize = readU32(bytes[pos + row_required_count_offset ..][0..4]);
        const excluded_count: usize = readU32(bytes[pos + row_excluded_count_offset ..][0..4]);
        pos += row_prefix_len + wire_len +
            (confirmed_count + required_count + excluded_count) * @sizeOf(u64);
    }
    return pos;
}

test "relay v2 event log prepared accept abort duplicate and conflict are byte inert" {
    const sign = @import("../crypto/sign.zig");
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x41)));
    defer kp.deinit();
    var first = try makeTestWire(testing.allocator, &kp, 1, "first");
    defer first.deinit(testing.allocator);
    var second = try makeTestWire(testing.allocator, &kp, 2, "other");
    defer second.deinit(testing.allocator);
    const required = [_]u64{ 7, 8, 9 };
    var log = try EventLog.init(testing.allocator, .{ .max_rows = 4 });
    defer log.deinit();

    try testing.expectEqual(ReserveOutcome.inserted, try log.reserveAccepted(first.id, first.bytes, 7, 8, &required));
    try testing.expect(!log.isConfirmedBy(first.id, 8));
    const retained = log.viewFor(first.id).?;
    try testing.expectEqualSlices(u8, &first.id, &retained.relay_id);
    try testing.expectEqualSlices(u64, &required, retained.required_nodes);
    try testing.expectEqualSlices(u8, first.bytes, log.wireFor(first.id).?);
    try testing.expect(log.viewFor(second.id) == null);
    try testing.expect(log.wireFor(second.id) == null);
    const before = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);

    try testing.expectEqual(ReserveOutcome.exact_duplicate, try log.reserveAccepted(first.id, first.bytes, 7, 8, &required));
    const duplicate = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(duplicate);
    try testing.expectEqualSlices(u8, before, duplicate);

    try testing.expectEqual(ReserveOutcome.conflict, try log.reserveAccepted(first.id, second.bytes, 7, null, &required));
    const after_conflict = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after_conflict);
    try testing.expectEqualSlices(u8, before, after_conflict);

    var aborted = try takeReady(try log.prepareAccepted(first.id, first.bytes, 7, 9, &required));
    aborted.abort();
    aborted.deinit();
    const after_abort = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after_abort);
    try testing.expectEqualSlices(u8, before, after_abort);
}

test "relay v2 event log rejects full row before cryptographic work and freezes bounds" {
    const sign = @import("../crypto/sign.zig");
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x42)));
    defer kp.deinit();
    var first = try makeTestWire(testing.allocator, &kp, 1, "first");
    defer first.deinit(testing.allocator);
    var second = try makeTestWire(testing.allocator, &kp, 2, "second");
    defer second.deinit(testing.allocator);
    const required = [_]u64{ 7, 8 };
    var log = try EventLog.init(testing.allocator, .{ .max_rows = 1 });
    defer log.deinit();
    _ = try log.reserveAccepted(first.id, first.bytes, 7, null, &required);
    const before = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);
    try testing.expectError(error.CapacityExceeded, log.reserveAccepted(second.id, &.{0xff}, 7, null, &required));
    const after = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);

    log.config.max_rows = 2;
    try testing.expectError(error.ConfigMismatch, log.encodeCheckpoint(testing.allocator));
    try testing.expectError(error.ConfigMismatch, log.prepareAccepted(second.id, second.bytes, 7, null, &required));
}

test "relay v2 event log ingress is one-sweep exclusion not durable confirmation" {
    const sign = @import("../crypto/sign.zig");
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x43)));
    defer kp.deinit();
    var wire = try makeTestWire(testing.allocator, &kp, 1, "ingress");
    defer wire.deinit(testing.allocator);
    const required = [_]u64{ 7, 8 };
    var log = try EventLog.init(testing.allocator, .{ .max_rows = 4 });
    defer log.deinit();
    _ = try log.reserveAccepted(wire.id, wire.bytes, 7, 8, &required);
    try testing.expect(log.isConfirmedBy(wire.id, 7));
    try testing.expect(!log.isConfirmedBy(wire.id, 8));
    try testing.expectEqualSlices(u64, &.{8}, log.viewAt(0).excluded_once_nodes);

    var page: [1]PageItem = undefined;
    try testing.expectEqual(@as(usize, 0), try log.collectPageForNode(8, &page));
    try testing.expectEqual(@as(usize, 1), try log.collectPageForNode(8, &page));
    try testing.expect(idsEqual(wire.id, page[0].relay_id));
}

test "relay v2 event log pages only event-time required missing coverage" {
    const sign = @import("../crypto/sign.zig");
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x44)));
    defer kp.deinit();
    var first = try makeTestWire(testing.allocator, &kp, 1, "first");
    defer first.deinit(testing.allocator);
    var second = try makeTestWire(testing.allocator, &kp, 2, "second");
    defer second.deinit(testing.allocator);
    var third = try makeTestWire(testing.allocator, &kp, 3, "third");
    defer third.deinit(testing.allocator);
    const required = [_]u64{ 7, 8, 99 };
    var log = try EventLog.init(testing.allocator, .{ .max_rows = 4 });
    defer log.deinit();
    _ = try log.reserveAccepted(first.id, first.bytes, 7, null, &required);
    _ = try log.reserveAccepted(second.id, second.bytes, 7, null, &required);
    _ = try log.reserveAccepted(third.id, third.bytes, 7, null, &required);
    try testing.expectEqual(ConfirmationOutcome.confirmed, try log.confirmAuthenticatedDurableAck(second.id, 99));
    try testing.expectEqual(ConfirmationOutcome.already_confirmed, try log.confirmAuthenticatedDurableAck(second.id, 99));

    var page: [3]PageItem = undefined;
    try testing.expectEqual(@as(usize, 1), try log.collectPageForNode(99, &page));
    try testing.expect(idsEqual(first.id, page[0].relay_id));
    try testing.expectEqual(@as(u64, 1), page[0].hlc);
    try testing.expectEqual(ConfirmationOutcome.confirmed, try log.confirmAuthenticatedDurableAck(first.id, 99));
    try testing.expectEqual(@as(usize, 1), try log.collectPageForNode(99, &page));
    try testing.expect(idsEqual(third.id, page[0].relay_id));
    try testing.expectEqual(@as(u64, 3), page[0].hlc);
    try testing.expectEqual(@as(usize, 0), try log.collectPageForNode(100, &page));
}

test "relay v2 event log checkpointed cursor reaches row 33 after restore" {
    const sign = @import("../crypto/sign.zig");
    const config = Config{ .max_rows = 33 };
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x45)));
    defer kp.deinit();
    var wires: [33]TestWire = undefined;
    var initialized: usize = 0;
    defer for (wires[0..initialized]) |*wire| wire.deinit(testing.allocator);
    const required = [_]u64{ 7, 99 };
    var log = try EventLog.init(testing.allocator, config);
    defer log.deinit();
    for (0..wires.len) |index| {
        wires[index] = try makeTestWire(testing.allocator, &kp, index + 1, "fairness");
        initialized += 1;
        _ = try log.reserveAccepted(wires[index].id, wires[index].bytes, 7, null, &required);
    }
    var page: [1]PageItem = undefined;
    for (0..32) |index| {
        try testing.expectEqual(@as(usize, 1), try log.collectPageForNode(99, &page));
        try testing.expectEqual(@as(u64, index + 1), page[0].hlc);
        try testing.expect(idsEqual(wires[index].id, page[0].relay_id));
        try testing.expectEqual(
            ConfirmationOutcome.confirmed_and_retired,
            try log.confirmAuthenticatedDurableAck(page[0].relay_id, 99),
        );
    }
    const checkpoint = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    var restored = try EventLog.decodeCheckpoint(testing.allocator, config, checkpoint);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 1), try restored.collectPageForNode(99, &page));
    try testing.expectEqual(@as(u64, 33), page[0].hlc);
    try testing.expect(idsEqual(wires[32].id, page[0].relay_id));
}

test "relay v2 event log scrambled 129 row backlog stays ascending through RVG2 window" {
    const sign = @import("../crypto/sign.zig");
    const replay_guard = @import("relay_v2_replay_guard.zig");
    const config = Config{ .max_rows = 129 };
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x5c)));
    defer kp.deinit();
    var wires: [129]TestWire = undefined;
    var initialized: usize = 0;
    defer for (wires[0..initialized]) |*wire| wire.deinit(testing.allocator);
    for (0..wires.len) |index| {
        wires[index] = try makeTestWire(testing.allocator, &kp, @intCast(index + 1), "scrambled-window");
        initialized += 1;
    }

    const required = [_]u64{ 7, 8, 99 };
    var log = try EventLog.init(testing.allocator, config);
    defer log.deinit();
    // 67 is coprime to 129, so this visits every row exactly once while
    // deliberately destroying HLC insertion order.
    for (0..wires.len) |iteration| {
        const index = (iteration * 67) % wires.len;
        _ = try log.reserveAccepted(wires[index].id, wires[index].bytes, 7, null, &required);
    }

    var guard = try replay_guard.Guard.init(testing.allocator, .{});
    defer guard.deinit();
    var page: [8]PageItem = undefined;
    for (0..wires.len) |index| {
        try testing.expectEqual(@as(usize, 1), try log.collectPageForNode(99, &page));
        try testing.expectEqual(@as(u64, @intCast(index + 1)), page[0].hlc);
        try testing.expect(idsEqual(wires[index].id, page[0].relay_id));
        var owned = try message_relay_v2.decode(testing.allocator, page[0].wire);
        defer owned.deinit(testing.allocator);
        switch (try guard.admitMessage(owned.msg)) {
            .accepted => |id| try testing.expect(idsEqual(page[0].relay_id, id)),
            else => return error.TestUnexpectedResult,
        }
        try testing.expectEqual(
            ConfirmationOutcome.confirmed,
            try log.confirmAuthenticatedDurableAck(page[0].relay_id, 99),
        );
    }
    try testing.expectEqual(@as(usize, 0), try log.collectPageForNode(99, &page));
}

test "relay v2 event log rotates origin heads fairly and restores mid page" {
    const sign = @import("../crypto/sign.zig");
    const config = Config{ .max_rows = 9, .max_confirmed_nodes_per_row = 4, .max_cursor_nodes = 4 };
    var kp_a = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x61)));
    defer kp_a.deinit();
    var kp_b = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x62)));
    defer kp_b.deinit();
    var kp_c = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x63)));
    defer kp_c.deinit();
    const keys = [_]*const sign.KeyPair{ &kp_a, &kp_b, &kp_c };
    var wires: [3][3]TestWire = undefined;
    var initialized: [3]usize = @splat(0);
    defer for (&wires, 0..) |*origin_wires, origin| {
        for (origin_wires[0..initialized[origin]]) |*wire| wire.deinit(testing.allocator);
    };
    for (keys, 0..) |kp, origin| {
        for (0..3) |index| {
            wires[origin][index] = try makeTestWire(testing.allocator, kp, @intCast(index + 1), "origin-fairness");
            initialized[origin] += 1;
        }
    }

    const required = [_]u64{ 7, 8, 99 };
    var log = try EventLog.init(testing.allocator, config);
    defer log.deinit();
    var reverse_hlc: usize = 3;
    while (reverse_hlc != 0) {
        reverse_hlc -= 1;
        var reverse_origin: usize = keys.len;
        while (reverse_origin != 0) {
            reverse_origin -= 1;
            const wire = wires[reverse_origin][reverse_hlc];
            _ = try log.reserveAccepted(wire.id, wire.bytes, 7, null, &required);
        }
    }

    var page: [2]PageItem = undefined;
    var next_hlc: [3]u64 = @splat(1);
    var first_round_origins: [3]bool = @splat(false);
    const first_count = try log.collectPageForNode(99, &page);
    try testing.expectEqual(@as(usize, 2), first_count);
    for (page[0..first_count]) |item| {
        var origin_index: ?usize = null;
        for (keys, 0..) |kp, index| if (originEqual(item.origin_pubkey, kp.public_key)) {
            origin_index = index;
            break;
        };
        const origin = origin_index orelse return error.TestUnexpectedResult;
        try testing.expectEqual(next_hlc[origin], item.hlc);
        next_hlc[origin] += 1;
        first_round_origins[origin] = true;
        _ = try log.confirmAuthenticatedDurableAck(item.relay_id, 99);
    }

    const checkpoint = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    var restored = try EventLog.decodeCheckpoint(testing.allocator, config, checkpoint);
    defer restored.deinit();
    var emitted = first_count;
    while (emitted < 9) {
        const count = try restored.collectPageForNode(99, &page);
        try testing.expect(count != 0);
        for (page[0..count]) |item| {
            var origin_index: ?usize = null;
            for (keys, 0..) |kp, index| if (originEqual(item.origin_pubkey, kp.public_key)) {
                origin_index = index;
                break;
            };
            const origin = origin_index orelse return error.TestUnexpectedResult;
            try testing.expectEqual(next_hlc[origin], item.hlc);
            next_hlc[origin] += 1;
            if (emitted < 3) first_round_origins[origin] = true;
            _ = try restored.confirmAuthenticatedDurableAck(item.relay_id, 99);
            emitted += 1;
        }
        if (emitted >= 3)
            try testing.expect(first_round_origins[0] and first_round_origins[1] and first_round_origins[2]);
    }
    try testing.expectEqualSlices(u64, &.{ 4, 4, 4 }, &next_hlc);
    try testing.expectEqual(@as(usize, 0), try restored.collectPageForNode(99, &page));
}

test "relay v2 event log rejects a second identity at one origin HLC atomically" {
    const sign = @import("../crypto/sign.zig");
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x64)));
    defer kp.deinit();
    var first = try makeTestWire(testing.allocator, &kp, 77, "first identity");
    defer first.deinit(testing.allocator);
    var equivocation = try makeTestWire(testing.allocator, &kp, 77, "second identity");
    defer equivocation.deinit(testing.allocator);
    const required = [_]u64{ 7, 8 };
    var log = try EventLog.init(testing.allocator, .{ .max_rows = 2 });
    defer log.deinit();
    _ = try log.reserveAccepted(first.id, first.bytes, 7, null, &required);
    const before = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);
    try testing.expectError(
        error.DuplicateEntry,
        log.reserveAccepted(equivocation.id, equivocation.bytes, 7, null, &required),
    );
    const after = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "relay v2 event log required membership gates safe retirement" {
    const sign = @import("../crypto/sign.zig");
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x46)));
    defer kp.deinit();
    var wire = try makeTestWire(testing.allocator, &kp, 1, "partition");
    defer wire.deinit(testing.allocator);
    const required = [_]u64{ 7, 8, 9 };
    var log = try EventLog.init(testing.allocator, .{ .max_rows = 4 });
    defer log.deinit();
    _ = try log.reserveAccepted(wire.id, wire.bytes, 7, null, &required);
    const before_ack = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before_ack);
    var aborted_ack = try log.prepareAuthenticatedDurableAck(wire.id, 8);
    aborted_ack.abort();
    aborted_ack.deinit();
    const after_aborted_ack = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after_aborted_ack);
    try testing.expectEqualSlices(u8, before_ack, after_aborted_ack);
    try testing.expectEqual(ConfirmationOutcome.confirmed, try log.confirmAuthenticatedDurableAck(wire.id, 8));
    try testing.expectEqual(@as(usize, 1), log.len());
    try testing.expectError(error.NodeNotRequired, log.confirmAuthenticatedDurableAck(wire.id, 10));
    try testing.expectEqual(ConfirmationOutcome.confirmed_and_retired, try log.confirmAuthenticatedDurableAck(wire.id, 9));
    try testing.expectEqual(@as(usize, 0), log.len());
}

test "relay v2 event log later membership is not retroactive and configured retirement is explicit" {
    const sign = @import("../crypto/sign.zig");
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x47)));
    defer kp.deinit();
    var wire = try makeTestWire(testing.allocator, &kp, 1, "membership");
    defer wire.deinit(testing.allocator);
    var survivor = try makeTestWire(testing.allocator, &kp, 2, "survivor");
    defer survivor.deinit(testing.allocator);
    const original = [_]u64{ 7, 8, 9 };
    const later = [_]u64{ 7, 8, 9, 99 };
    const survivor_required = [_]u64{ 7, 8 };
    var log = try EventLog.init(testing.allocator, .{ .max_rows = 4 });
    defer log.deinit();
    _ = try log.reserveAccepted(wire.id, wire.bytes, 7, null, &original);
    _ = try log.reserveAccepted(survivor.id, survivor.bytes, 7, null, &survivor_required);
    try testing.expectEqual(ReserveOutcome.exact_duplicate, try log.reserveAccepted(wire.id, wire.bytes, 7, 99, &later));
    const wire_index = lowerBoundRows(log.rows.items, wire.id);
    try testing.expectEqualSlices(u64, &original, log.viewAt(wire_index).required_nodes);
    try testing.expectEqual(@as(usize, 0), log.viewAt(wire_index).excluded_once_nodes.len);
    try testing.expectEqual(ConfirmationOutcome.confirmed, try log.confirmAuthenticatedDurableAck(wire.id, 8));
    var page: [1]PageItem = undefined;
    try testing.expectEqual(@as(usize, 1), try log.collectPageForNode(9, &page));

    const before = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(before);
    var aborted = try log.prepareConfiguredNodeRetirement(9);
    aborted.abort();
    aborted.deinit();
    const after_abort = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(after_abort);
    try testing.expectEqualSlices(u8, before, after_abort);

    var retirement = try log.prepareConfiguredNodeRetirement(9);
    defer retirement.deinit();
    const result = retirement.commit();
    try testing.expectEqual(@as(usize, 1), result.rows_changed);
    try testing.expectEqual(@as(usize, 1), result.rows_retired);
    try testing.expect(result.cursor_removed);
    try testing.expectEqual(@as(usize, 1), log.len());
    try testing.expect(log.contains(survivor.id));
}

test "relay v2 event log strict checkpoint preserves required sets and rejects malformed state" {
    const sign = @import("../crypto/sign.zig");
    const config = Config{ .max_rows = 4, .max_confirmed_nodes_per_row = 4, .max_cursor_nodes = 4 };
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x48)));
    defer kp.deinit();
    var first = try makeTestWire(testing.allocator, &kp, 1, "first");
    defer first.deinit(testing.allocator);
    var second = try makeTestWire(testing.allocator, &kp, 2, "second");
    defer second.deinit(testing.allocator);
    const required = [_]u64{ 7, 8, 9 };
    var log = try EventLog.init(testing.allocator, config);
    defer log.deinit();
    _ = try log.reserveAccepted(first.id, first.bytes, 7, null, &required);
    _ = try log.reserveAccepted(second.id, second.bytes, 7, null, &required);
    _ = try log.confirmAuthenticatedDurableAck(first.id, 9);
    var page: [1]PageItem = undefined;
    _ = try log.collectPageForNode(8, &page);
    const checkpoint = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    var restored = try EventLog.decodeCheckpoint(testing.allocator, config, checkpoint);
    defer restored.deinit();
    try testing.expectEqualSlices(u64, &required, restored.viewAt(0).required_nodes);
    const exact = try restored.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(exact);
    try testing.expectEqualSlices(u8, checkpoint, exact);
    var mismatched_config = config;
    mismatched_config.max_rows += 1;
    try testing.expectError(error.ConfigMismatch, EventLog.decodeCheckpoint(testing.allocator, mismatched_config, checkpoint));

    const corrupt = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(corrupt);
    corrupt[corrupt.len - 1] ^= 1;
    try testing.expectError(error.ChecksumMismatch, EventLog.decodeCheckpoint(testing.allocator, config, corrupt));

    const version = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(version);
    version[4] +%= 1;
    try testing.expectError(error.UnsupportedVersion, EventLog.decodeCheckpoint(testing.allocator, config, version));

    const legacy_v2 = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(legacy_v2);
    legacy_v2[4] = 2;
    try testing.expectError(error.UnsupportedVersion, EventLog.decodeCheckpoint(testing.allocator, config, legacy_v2));

    const unknown = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(unknown);
    unknown[5] = 1;
    try testing.expectError(error.UnknownFlags, EventLog.decodeCheckpoint(testing.allocator, config, unknown));

    const trailing = try testing.allocator.alloc(u8, checkpoint.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..checkpoint.len], checkpoint);
    trailing[checkpoint.len] = 0;
    try testing.expectError(error.TrailingBytes, EventLog.decodeCheckpoint(testing.allocator, config, trailing));

    const mismatched_metadata = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(mismatched_metadata);
    const stored_origin_node = readU64(mismatched_metadata[checkpoint_header_len + row_origin_node_offset ..][0..8]);
    writeU64(
        mismatched_metadata[checkpoint_header_len + row_origin_node_offset ..][0..8],
        stored_origin_node +| 1,
    );
    checkpointChecksum(
        mismatched_metadata[0 .. mismatched_metadata.len - checksum_len],
        mismatched_metadata[mismatched_metadata.len - checksum_len ..][0..checksum_len],
    );
    try testing.expectError(
        error.InvalidWire,
        EventLog.decodeCheckpoint(testing.allocator, config, mismatched_metadata),
    );

    const duplicate = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(duplicate);
    const first_offset = checkpoint_header_len;
    const first_id: RelayId = duplicate[first_offset..][0..@sizeOf(RelayId)].*;
    const first_wire_len: usize = readU32(duplicate[first_offset + row_wire_len_offset ..][0..4]);
    const first_confirmed: usize = readU32(duplicate[first_offset + row_confirmed_count_offset ..][0..4]);
    const first_required: usize = readU32(duplicate[first_offset + row_required_count_offset ..][0..4]);
    const first_excluded: usize = readU32(duplicate[first_offset + row_excluded_count_offset ..][0..4]);
    const second_offset = first_offset + row_prefix_len + first_wire_len +
        (first_confirmed + first_required + first_excluded) * @sizeOf(u64);
    @memcpy(duplicate[second_offset..][0..@sizeOf(RelayId)], &first_id);
    checkpointChecksum(duplicate[0 .. duplicate.len - checksum_len], duplicate[duplicate.len - checksum_len ..][0..checksum_len]);
    try testing.expectError(error.DuplicateEntry, EventLog.decodeCheckpoint(testing.allocator, config, duplicate));

    const bad_required = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(bad_required);
    const required_offset = first_offset + row_prefix_len + first_wire_len;
    @memcpy(bad_required[required_offset + 8 ..][0..8], bad_required[required_offset..][0..8]);
    checkpointChecksum(bad_required[0 .. bad_required.len - checksum_len], bad_required[bad_required.len - checksum_len ..][0..checksum_len]);
    try testing.expectError(error.DuplicateNode, EventLog.decodeCheckpoint(testing.allocator, config, bad_required));

    const bad_cursor = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(bad_cursor);
    const cursor_offset = rowsEndInCheckpoint(bad_cursor);
    @memset(bad_cursor[cursor_offset + 8 ..][0..message_relay_v2.pubkey_len], 0);
    checkpointChecksum(bad_cursor[0 .. bad_cursor.len - checksum_len], bad_cursor[bad_cursor.len - checksum_len ..][0..checksum_len]);
    try testing.expectError(error.CursorTargetMissing, EventLog.decodeCheckpoint(testing.allocator, config, bad_cursor));
}

test "relay v2 event log two peer cursors remain valid across retirement checkpoint" {
    const sign = @import("../crypto/sign.zig");
    const config = Config{ .max_rows = 4, .max_confirmed_nodes_per_row = 4, .max_cursor_nodes = 4 };
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x4b)));
    defer kp.deinit();
    var first = try makeTestWire(testing.allocator, &kp, 1, "first");
    defer first.deinit(testing.allocator);
    var second = try makeTestWire(testing.allocator, &kp, 2, "second");
    defer second.deinit(testing.allocator);
    var third = try makeTestWire(testing.allocator, &kp, 3, "third");
    defer third.deinit(testing.allocator);
    const required = [_]u64{ 7, 8, 9 };
    var log = try EventLog.init(testing.allocator, config);
    defer log.deinit();
    _ = try log.reserveAccepted(first.id, first.bytes, 7, null, &required);
    _ = try log.reserveAccepted(second.id, second.bytes, 7, null, &required);
    _ = try log.reserveAccepted(third.id, third.bytes, 7, null, &required);

    var one: [1]PageItem = undefined;
    try testing.expectEqual(@as(usize, 1), try log.collectPageForNode(8, &one));
    const retired_id = one[0].relay_id;
    try testing.expectEqual(@as(usize, 1), try log.collectPageForNode(9, &one));
    try testing.expect(idsEqual(retired_id, one[0].relay_id));
    try testing.expectEqual(ConfirmationOutcome.confirmed, try log.confirmAuthenticatedDurableAck(retired_id, 8));
    try testing.expectEqual(ConfirmationOutcome.confirmed_and_retired, try log.confirmAuthenticatedDurableAck(retired_id, 9));
    try testing.expectEqual(@as(usize, 2), log.len());

    const checkpoint = try log.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    var restored = try EventLog.decodeCheckpoint(testing.allocator, config, checkpoint);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 1), try restored.collectPageForNode(8, &one));
    try testing.expect(!idsEqual(retired_id, one[0].relay_id));
    try testing.expectEqual(@as(usize, 1), try restored.collectPageForNode(9, &one));
    try testing.expect(!idsEqual(retired_id, one[0].relay_id));
}

test "relay v2 event log preparation and decode are allocation-failure atomic" {
    const sign = @import("../crypto/sign.zig");
    const config = Config{ .max_rows = 4, .max_confirmed_nodes_per_row = 4 };
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x49)));
    defer kp.deinit();
    var wire = try makeTestWire(testing.allocator, &kp, 1, "allocation sweep");
    defer wire.deinit(testing.allocator);
    const required = [_]u64{ 7, 8, 9 };

    const PrepareSweep = struct {
        fn run(allocator: std.mem.Allocator, cfg: Config, signed_wire: TestWire, membership: []const u64) !void {
            var candidate = try EventLog.init(allocator, cfg);
            defer candidate.deinit();
            const before = try candidate.encodeCheckpoint(testing.allocator);
            defer testing.allocator.free(before);
            var prepared = takeReady(candidate.prepareAccepted(signed_wire.id, signed_wire.bytes, 7, 8, membership) catch |err| {
                const after_failure = try candidate.encodeCheckpoint(testing.allocator);
                defer testing.allocator.free(after_failure);
                try testing.expectEqualSlices(u8, before, after_failure);
                return err;
            }) catch return error.TestUnexpectedResult;
            prepared.abort();
            prepared.deinit();
            const after_abort = try candidate.encodeCheckpoint(testing.allocator);
            defer testing.allocator.free(after_abort);
            try testing.expectEqualSlices(u8, before, after_abort);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, PrepareSweep.run, .{ config, wire, &required });

    var source = try EventLog.init(testing.allocator, config);
    defer source.deinit();
    _ = try source.reserveAccepted(wire.id, wire.bytes, 7, 8, &required);
    const checkpoint = try source.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(checkpoint);
    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, cfg: Config, encoded: []const u8) !void {
            var candidate = try EventLog.decodeCheckpoint(allocator, cfg, encoded);
            defer candidate.deinit();
            try testing.expectEqual(@as(usize, 1), candidate.len());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, DecodeSweep.run, .{ config, checkpoint });

    const CollectSweep = struct {
        fn run(allocator: std.mem.Allocator, cfg: Config, encoded: []const u8) !void {
            var candidate = try EventLog.decodeCheckpoint(allocator, cfg, encoded);
            defer candidate.deinit();
            const before = try candidate.encodeCheckpoint(testing.allocator);
            defer testing.allocator.free(before);
            var page: [1]PageItem = undefined;
            const count = candidate.collectPageForNode(9, &page) catch |err| {
                const after_failure = try candidate.encodeCheckpoint(testing.allocator);
                defer testing.allocator.free(after_failure);
                try testing.expectEqualSlices(u8, before, after_failure);
                return err;
            };
            try testing.expectEqual(@as(usize, 1), count);
        }
    };
    // The source ingress excludes node 8, while node 9 is missing and therefore
    // forces the first durable fairness-cursor allocation.
    try testing.checkAllAllocationFailures(testing.allocator, CollectSweep.run, .{ config, checkpoint });
}

test "relay v2 event log empty trust roots cannot fall back to local-only membership" {
    const sign = @import("../crypto/sign.zig");
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(0x4a)));
    defer kp.deinit();
    var wire = try makeTestWire(testing.allocator, &kp, 1, "single");
    defer wire.deinit(testing.allocator);
    const required = [_]u64{7};
    var log = try EventLog.init(testing.allocator, .{ .max_rows = 1 });
    defer log.deinit();
    try testing.expectError(error.InvalidMembership, log.reserveAccepted(wire.id, wire.bytes, 7, null, &required));
    try testing.expectEqual(@as(usize, 0), log.len());
}
