// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Eg-walker: replay a lotus edit-event DAG into the convergent sequence CRDT (#14).
//!
//! Lotus stores edit events in a causal DAG; `seq_crdt` is the convergent
//! document they fold into. This is the walker that joins them: it materializes
//! the document by visiting events in `Dag.causalOrder` (parents before children,
//! so each insert's origin element already exists) and applying each to a
//! `SeqCrdt`. Because the sequence CRDT is order-independent for concurrent ops,
//! two replicas whose DAGs hold the same events — however they were inserted —
//! replay to the identical document.
//!
//! Edit ops are carried in the opaque lotus `Event.payload` with this compact
//! little-endian encoding:
//!   insert: [0][id.lamport u64][id.replica u32][has_origin u8]
//!           ([origin.lamport u64][origin.replica u32] if has_origin)[ch u8]
//!   delete: [1][target.lamport u64][target.replica u32]
const std = @import("std");

const lotus = @import("lotus.zig");
const seq_crdt = @import("seq_crdt.zig");

pub const OpId = seq_crdt.OpId;

pub const Error = lotus.DagError || seq_crdt.Error || error{MalformedOp};

pub const EditOp = union(enum) {
    insert: struct { id: OpId, origin: ?OpId, ch: u8 },
    delete: struct { target: OpId },
};

/// Maximum encoded op size (insert with origin).
pub const max_op_bytes: usize = 1 + 8 + 4 + 1 + 8 + 4 + 1;

pub fn encodeOp(op: EditOp, out: []u8) error{MalformedOp}![]const u8 {
    switch (op) {
        .insert => |ins| {
            const has_origin = ins.origin != null;
            const need: usize = 1 + 8 + 4 + 1 + (if (has_origin) @as(usize, 12) else 0) + 1;
            if (out.len < need) return error.MalformedOp;
            var i: usize = 0;
            out[i] = 0;
            i += 1;
            std.mem.writeInt(u64, out[i..][0..8], ins.id.lamport, .little);
            i += 8;
            std.mem.writeInt(u32, out[i..][0..4], ins.id.replica, .little);
            i += 4;
            out[i] = @intFromBool(has_origin);
            i += 1;
            if (ins.origin) |o| {
                std.mem.writeInt(u64, out[i..][0..8], o.lamport, .little);
                i += 8;
                std.mem.writeInt(u32, out[i..][0..4], o.replica, .little);
                i += 4;
            }
            out[i] = ins.ch;
            i += 1;
            return out[0..i];
        },
        .delete => |del| {
            if (out.len < 1 + 8 + 4) return error.MalformedOp;
            out[0] = 1;
            std.mem.writeInt(u64, out[1..][0..8], del.target.lamport, .little);
            std.mem.writeInt(u32, out[9..][0..4], del.target.replica, .little);
            return out[0 .. 1 + 8 + 4];
        },
    }
}

pub fn decodeOp(bytes: []const u8) error{MalformedOp}!EditOp {
    if (bytes.len < 1) return error.MalformedOp;
    switch (bytes[0]) {
        0 => {
            if (bytes.len < 1 + 8 + 4 + 1) return error.MalformedOp;
            var i: usize = 1;
            const id = OpId{
                .lamport = std.mem.readInt(u64, bytes[i..][0..8], .little),
                .replica = std.mem.readInt(u32, bytes[i + 8 ..][0..4], .little),
            };
            i += 12;
            const has_origin = bytes[i] != 0;
            i += 1;
            var origin: ?OpId = null;
            if (has_origin) {
                if (bytes.len < i + 12 + 1) return error.MalformedOp;
                origin = .{
                    .lamport = std.mem.readInt(u64, bytes[i..][0..8], .little),
                    .replica = std.mem.readInt(u32, bytes[i + 8 ..][0..4], .little),
                };
                i += 12;
            }
            if (bytes.len < i + 1) return error.MalformedOp;
            return .{ .insert = .{ .id = id, .origin = origin, .ch = bytes[i] } };
        },
        1 => {
            if (bytes.len < 1 + 8 + 4) return error.MalformedOp;
            return .{ .delete = .{ .target = .{
                .lamport = std.mem.readInt(u64, bytes[1..][0..8], .little),
                .replica = std.mem.readInt(u32, bytes[9..][0..4], .little),
            } } };
        },
        else => return error.MalformedOp,
    }
}

/// Build a lotus edit event for `op` with the given DAG `parents` (which should
/// be the events that created the op's causal predecessors). Inserts the event
/// into `dag` and returns its CID.
pub fn appendOp(dag: *lotus.Dag, parents: []const lotus.Cid, op: EditOp) Error!lotus.Cid {
    var buf: [max_op_bytes]u8 = undefined;
    const payload = try encodeOp(op, &buf);
    return dag.insert(.{ .parents = parents, .payload = payload });
}

/// Replay the whole DAG into a document (caller owns the bytes). Visits events in
/// causal order so every insert's origin is already present.
pub fn replay(allocator: std.mem.Allocator, dag: *const lotus.Dag) Error![]u8 {
    var seq = seq_crdt.SeqCrdt.init(allocator);
    defer seq.deinit();

    const order = try dag.causalOrder();
    defer allocator.free(order);
    for (order) |cid| {
        const ev = dag.getEvent(cid) orelse return error.MalformedOp;
        switch (try decodeOp(ev.payload)) {
            .insert => |ins| try seq.insert(ins.id, ins.origin, ins.ch),
            .delete => |del| seq.remove(del.target),
        }
    }
    return seq.text(allocator);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "edit op encode/decode round-trips (insert with/without origin, delete)" {
    var buf: [max_op_bytes]u8 = undefined;

    const with_origin = EditOp{ .insert = .{ .id = .{ .lamport = 7, .replica = 3 }, .origin = .{ .lamport = 2, .replica = 1 }, .ch = 'q' } };
    const w1 = try encodeOp(with_origin, &buf);
    const d1 = try decodeOp(w1);
    try testing.expect(d1.insert.id.eql(.{ .lamport = 7, .replica = 3 }));
    try testing.expect(d1.insert.origin.?.eql(.{ .lamport = 2, .replica = 1 }));
    try testing.expectEqual(@as(u8, 'q'), d1.insert.ch);

    const no_origin = EditOp{ .insert = .{ .id = .{ .lamport = 1, .replica = 0 }, .origin = null, .ch = 'a' } };
    const d2 = try decodeOp(try encodeOp(no_origin, &buf));
    try testing.expect(d2.insert.origin == null);

    const del = EditOp{ .delete = .{ .target = .{ .lamport = 5, .replica = 2 } } };
    const d3 = try decodeOp(try encodeOp(del, &buf));
    try testing.expect(d3.delete.target.eql(.{ .lamport = 5, .replica = 2 }));
}

test "replay folds a DAG of edits into the document" {
    const allocator = testing.allocator;
    var dag = lotus.Dag.init(allocator);
    defer dag.deinit();

    // "a", then "b" after a, then delete a  ->  "b"
    const a_id = OpId{ .lamport = 1, .replica = 0 };
    const b_id = OpId{ .lamport = 2, .replica = 0 };
    const ca = try appendOp(&dag, &.{}, .{ .insert = .{ .id = a_id, .origin = null, .ch = 'a' } });
    const cb = try appendOp(&dag, &.{ca}, .{ .insert = .{ .id = b_id, .origin = a_id, .ch = 'b' } });
    _ = try appendOp(&dag, &.{cb}, .{ .delete = .{ .target = a_id } });

    const doc = try replay(allocator, &dag);
    defer allocator.free(doc);
    try testing.expectEqualStrings("b", doc);
}

test "two replicas with concurrent edits replay to the identical document" {
    const allocator = testing.allocator;

    const x = OpId{ .lamport = 1, .replica = 0 };
    const a = OpId{ .lamport = 2, .replica = 1 }; // concurrent insert after x
    const b = OpId{ .lamport = 2, .replica = 2 }; // concurrent insert after x

    // Replica 1 inserts the events in order x, a, b.
    var dag1 = lotus.Dag.init(allocator);
    defer dag1.deinit();
    const x1 = try appendOp(&dag1, &.{}, .{ .insert = .{ .id = x, .origin = null, .ch = 'x' } });
    _ = try appendOp(&dag1, &.{x1}, .{ .insert = .{ .id = a, .origin = x, .ch = 'a' } });
    _ = try appendOp(&dag1, &.{x1}, .{ .insert = .{ .id = b, .origin = x, .ch = 'b' } });

    // Replica 2 inserts the same events in the opposite concurrent order.
    var dag2 = lotus.Dag.init(allocator);
    defer dag2.deinit();
    const x2 = try appendOp(&dag2, &.{}, .{ .insert = .{ .id = x, .origin = null, .ch = 'x' } });
    _ = try appendOp(&dag2, &.{x2}, .{ .insert = .{ .id = b, .origin = x, .ch = 'b' } });
    _ = try appendOp(&dag2, &.{x2}, .{ .insert = .{ .id = a, .origin = x, .ch = 'a' } });

    const doc1 = try replay(allocator, &dag1);
    defer allocator.free(doc1);
    const doc2 = try replay(allocator, &dag2);
    defer allocator.free(doc2);
    try testing.expectEqualStrings(doc1, doc2);
    try testing.expectEqualStrings("xba", doc1); // b (higher replica at l2) sorts first after x
}

test "malformed op payload is rejected" {
    try testing.expectError(error.MalformedOp, decodeOp(&.{}));
    try testing.expectError(error.MalformedOp, decodeOp(&.{0})); // insert header without body
    try testing.expectError(error.MalformedOp, decodeOp(&.{9})); // unknown kind
}
