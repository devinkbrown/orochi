//! Snowflake-style compact 64-bit identifiers.
//!
//! The layout is:
//!   * 42 bits: caller-supplied millisecond timestamp
//!   * 10 bits: node id
//!   * 12 bits: per-millisecond sequence
//!
//! This module is pure state transition logic. It never reads a clock and never
//! allocates; callers inject `now_ms` at the edge.

const std = @import("std");

/// Number of timestamp bits in an encoded id.
pub const TIMESTAMP_BITS: u6 = 42;

/// Number of node-id bits in an encoded id.
pub const NODE_BITS: u6 = 10;

/// Number of sequence bits in an encoded id.
pub const SEQUENCE_BITS: u6 = 12;

/// Bit position where the timestamp field begins.
pub const TIMESTAMP_SHIFT: u6 = NODE_BITS + SEQUENCE_BITS;

/// Bit position where the node field begins.
pub const NODE_SHIFT: u6 = SEQUENCE_BITS;

/// Largest encodable timestamp in milliseconds.
pub const MAX_TIMESTAMP_MS: u64 = (1 << TIMESTAMP_BITS) - 1;

/// Largest encodable node id.
pub const MAX_NODE_ID: u16 = @intCast((1 << NODE_BITS) - 1);

/// Largest per-millisecond sequence value.
pub const MAX_SEQUENCE: u16 = @intCast((1 << SEQUENCE_BITS) - 1);

/// Mask for the encoded node-id field.
pub const NODE_MASK: u64 = (1 << NODE_BITS) - 1;

/// Mask for the encoded sequence field.
pub const SEQUENCE_MASK: u64 = (1 << SEQUENCE_BITS) - 1;

/// Configuration for a Snowflake-style id generator.
pub const Params = struct {
    /// Node id embedded in every id. Must fit in 10 bits.
    node_id: u16 = 0,
};

/// Errors returned while creating or advancing a generator.
pub const SnowflakeError = error{
    /// The configured node id does not fit in the 10-bit node field.
    InvalidNode,
    /// The requested or guarded timestamp cannot fit in the 42-bit field.
    TimestampOverflow,
};

/// Decoded fields from a compact id.
pub const Parts = struct {
    /// Millisecond timestamp field.
    ts: u64,
    /// Embedded node id.
    node: u16,
    /// Per-millisecond sequence field.
    seq: u16,
};

/// Stateful, monotonic Snowflake-style 64-bit id generator.
pub const Generator = struct {
    /// Node id embedded in generated ids.
    node_id: u16,
    /// Last timestamp emitted by this generator, or null before first use.
    last_ts: ?u64 = null,
    /// Last sequence value emitted for `last_ts`.
    sequence: u16 = 0,

    /// Construct a generator with validated parameters.
    pub fn init(params: Params) SnowflakeError!Generator {
        if (params.node_id > MAX_NODE_ID) return error.InvalidNode;
        return .{ .node_id = params.node_id };
    }

    /// Release generator resources.
    ///
    /// The generator owns no heap memory, so this is present for sibling-module
    /// symmetry and to make lifecycle management explicit.
    pub fn deinit(self: *Generator) void {
        self.* = undefined;
    }

    /// Return the next monotonic id for the caller-supplied timestamp.
    ///
    /// If `now_ms` moves backwards, the previous emitted timestamp is reused and
    /// only the sequence advances. If the 12-bit sequence is exhausted within a
    /// millisecond, the generator rolls to the next millisecond and resets the
    /// sequence to zero. It returns `TimestampOverflow` only when no 64-bit
    /// encoding remains possible.
    pub fn next(self: *Generator, now_ms: u64) SnowflakeError!u64 {
        if (now_ms > MAX_TIMESTAMP_MS) return error.TimestampOverflow;

        var ts = now_ms;
        if (self.last_ts) |last| {
            if (ts < last) ts = last;

            if (ts == last) {
                if (self.sequence == MAX_SEQUENCE) {
                    if (last == MAX_TIMESTAMP_MS) return error.TimestampOverflow;
                    ts = last + 1;
                    self.sequence = 0;
                } else {
                    self.sequence += 1;
                }
            } else {
                self.sequence = 0;
            }
        } else {
            self.sequence = 0;
        }

        self.last_ts = ts;
        return encode(ts, self.node_id, self.sequence);
    }
};

/// Decode an id into timestamp, node, and sequence fields.
pub fn parse(id: u64) Parts {
    return .{
        .ts = id >> TIMESTAMP_SHIFT,
        .node = @intCast((id >> NODE_SHIFT) & NODE_MASK),
        .seq = @intCast(id & SEQUENCE_MASK),
    };
}

fn encode(ts: u64, node: u16, seq: u16) u64 {
    return (ts << TIMESTAMP_SHIFT) |
        (@as(u64, node) << NODE_SHIFT) |
        @as(u64, seq);
}

const testing = std.testing;

test "next returns strictly increasing ids across increasing timestamps" {
    // Arrange.
    const allocator = testing.allocator;
    var ids = try allocator.alloc(u64, 4);
    defer allocator.free(ids);
    var generator = try Generator.init(.{ .node_id = 7 });
    defer generator.deinit();

    // Act.
    ids[0] = try generator.next(1_000);
    ids[1] = try generator.next(1_001);
    ids[2] = try generator.next(1_002);
    ids[3] = try generator.next(1_003);

    // Assert.
    try testing.expect(ids[0] < ids[1]);
    try testing.expect(ids[1] < ids[2]);
    try testing.expect(ids[2] < ids[3]);
    try testing.expectEqual(@as(u16, 7), parse(ids[3]).node);
}

test "next guards against backward timestamps by advancing sequence" {
    // Arrange.
    const allocator = testing.allocator;
    var ids = try allocator.alloc(u64, 3);
    defer allocator.free(ids);
    var generator = try Generator.init(.{ .node_id = 9 });
    defer generator.deinit();

    // Act.
    ids[0] = try generator.next(5_000);
    ids[1] = try generator.next(4_999);
    ids[2] = try generator.next(4_000);

    // Assert.
    try testing.expect(ids[0] < ids[1]);
    try testing.expect(ids[1] < ids[2]);
    try testing.expectEqual(Parts{ .ts = 5_000, .node = 9, .seq = 0 }, parse(ids[0]));
    try testing.expectEqual(Parts{ .ts = 5_000, .node = 9, .seq = 1 }, parse(ids[1]));
    try testing.expectEqual(Parts{ .ts = 5_000, .node = 9, .seq = 2 }, parse(ids[2]));
}

test "next rolls sequence overflow into the next millisecond" {
    // Arrange.
    const allocator = testing.allocator;
    var ids = try allocator.alloc(u64, @as(usize, MAX_SEQUENCE) + 2);
    defer allocator.free(ids);
    var generator = try Generator.init(.{ .node_id = 3 });
    defer generator.deinit();

    // Act.
    var index: usize = 0;
    while (index < ids.len) : (index += 1) {
        ids[index] = try generator.next(42);
    }

    // Assert.
    try testing.expectEqual(Parts{ .ts = 42, .node = 3, .seq = 0 }, parse(ids[0]));
    try testing.expectEqual(Parts{ .ts = 42, .node = 3, .seq = MAX_SEQUENCE }, parse(ids[MAX_SEQUENCE]));
    try testing.expectEqual(Parts{ .ts = 43, .node = 3, .seq = 0 }, parse(ids[@as(usize, MAX_SEQUENCE) + 1]));
    try testing.expect(ids[MAX_SEQUENCE] < ids[@as(usize, MAX_SEQUENCE) + 1]);
}

test "parse round-trips generated timestamp node and sequence fields" {
    // Arrange.
    const allocator = testing.allocator;
    var ids = try allocator.alloc(u64, 2);
    defer allocator.free(ids);
    var generator = try Generator.init(.{ .node_id = MAX_NODE_ID });
    defer generator.deinit();
    const ts: u64 = 1_700_000_000_123;

    // Act.
    ids[0] = try generator.next(ts);
    ids[1] = try generator.next(ts);
    const first = parse(ids[0]);
    const second = parse(ids[1]);

    // Assert.
    try testing.expectEqual(Parts{ .ts = ts, .node = MAX_NODE_ID, .seq = 0 }, first);
    try testing.expectEqual(Parts{ .ts = ts, .node = MAX_NODE_ID, .seq = 1 }, second);
}

test "init rejects node ids outside the encoded field" {
    // Arrange.
    const allocator = testing.allocator;
    var scratch = try allocator.alloc(u8, 1);
    defer allocator.free(scratch);
    scratch[0] = 0;

    // Act.
    const result = Generator.init(.{ .node_id = MAX_NODE_ID + 1 });

    // Assert.
    try testing.expectEqual(@as(u8, 0), scratch[0]);
    try testing.expectError(error.InvalidNode, result);
}

test "next reports timestamp overflow before mutating state" {
    // Arrange.
    const allocator = testing.allocator;
    var ids = try allocator.alloc(u64, 1);
    defer allocator.free(ids);
    var generator = try Generator.init(.{ .node_id = 1 });
    defer generator.deinit();
    ids[0] = try generator.next(MAX_TIMESTAMP_MS);

    // Act.
    const result = generator.next(MAX_TIMESTAMP_MS + 1);

    // Assert.
    try testing.expectError(error.TimestampOverflow, result);
    try testing.expectEqual(Parts{ .ts = MAX_TIMESTAMP_MS, .node = 1, .seq = 0 }, parse(ids[0]));
    try testing.expectEqual(@as(?u64, MAX_TIMESTAMP_MS), generator.last_ts);
    try testing.expectEqual(@as(u16, 0), generator.sequence);
}
