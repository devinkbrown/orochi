//! Sharded connection-table wrapper for the multi-reactor model.
//!
//! The single-reactor daemon owns ONE generational slab (`client.Table`) with
//! every id pinned to shard 0. The multi-reactor model splits ownership across N
//! reactors, each holding a disjoint shard. A reactor only ever touches the slab
//! for its own shard, so slot access needs no locking: the shard is the isolation
//! boundary, not a mutex.
//!
//! `ShardedTable` is a thin wrapper around N inner `client.Table` instances. It
//! does NOT reimplement slot allocation, generations, or the freelist — those all
//! live in the inner table generic. The wrapper only routes by `ClientId.shard`
//! and stamps the home shard into ids at alloc time.
//!
//! OWNERSHIP CONTRACT: each inner shard table must only be mutated by its owning
//! reactor. There is no cross-shard locking here by design. Work that targets a
//! client on another shard does NOT reach across via this wrapper; it is handed
//! to the owning reactor through the shard mailboxes (see daemon/shard.zig). This
//! wrapper is for same-shard, owner-thread access only.
const std = @import("std");
const client_model = @import("client.zig");

pub const ClientId = client_model.ClientId;
pub const ModelError = client_model.ModelError;

/// Routing/configuration errors distinct from the inner table's slab errors.
pub const ShardError = error{
    /// Requested shard index is outside `[0, num_shards)`.
    ShardOutOfRange,
    /// `init` was asked for zero shards or more than the `u12` id field allows.
    ShardCountInvalid,
};

const max_shards: usize = @as(usize, std.math.maxInt(u12)) + 1;

/// Sharded wrapper over `client.Table(Value, ClientId)`.
///
/// `Value` is the per-slot payload (typically `client.Client`). The inner table
/// type is fixed to be keyed by `ClientId` so the `.shard` field is available for
/// routing — that is the whole point of the wrapper.
pub fn ShardedTable(comptime Value: type) type {
    return struct {
        const Self = @This();

        /// The per-shard table type we wrap. This is the existing generational
        /// slab from client.zig — we do not reimplement slot allocation.
        pub const InnerTable = client_model.Table(Value, ClientId);

        allocator: std.mem.Allocator,
        /// One inner table per shard. Index == shard number. Each table's own
        /// `.shard` field is set to its index at init so the ids it mints (and
        /// the ids it validates) self-describe their home shard.
        shards: []InnerTable,

        /// Allocate `num_shards` per-shard tables, each pre-sized to
        /// `capacity_per_shard`. Shard `i`'s inner table is stamped with shard
        /// index `i` so every id it produces carries `.shard == i`.
        pub fn init(
            allocator: std.mem.Allocator,
            num_shards: usize,
            capacity_per_shard: usize,
        ) (ModelError || ShardError)!Self {
            if (num_shards == 0 or num_shards > max_shards) return error.ShardCountInvalid;

            const shards = try allocator.alloc(InnerTable, num_shards);
            // Track how many tables are fully initialized so cleanup on a later
            // failure only deinits the ones we actually created.
            var initialized: usize = 0;
            errdefer {
                for (shards[0..initialized]) |*table| table.deinit();
                allocator.free(shards);
            }

            for (shards, 0..) |*table, i| {
                table.* = InnerTable.init(allocator, @intCast(i));
                if (capacity_per_shard != 0) try table.reserve(capacity_per_shard);
                initialized += 1;
            }

            return .{
                .allocator = allocator,
                .shards = shards,
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.shards) |*table| table.deinit();
            self.allocator.free(self.shards);
            self.* = undefined;
        }

        /// Number of shards (inner tables) this wrapper owns.
        pub fn numShards(self: *const Self) usize {
            return self.shards.len;
        }

        /// Allocate a slot in `shard`'s table and return an id whose `.shard`
        /// equals `shard`. The inner table already stamps its own `.shard` into
        /// the id (set at init), so the returned id self-describes its home and
        /// will only ever resolve against this same shard's table.
        pub fn allocOn(self: *Self, shard: u12, value: Value) (ModelError || ShardError)!ClientId {
            const table = try self.tablePtr(shard);
            const id = try table.alloc(value);
            // Defensive: the inner table stamps `.shard` from its own field, which
            // we set to the shard index at init. Assert the invariant rather than
            // re-stamp, so a drift in the contract surfaces in debug builds.
            std.debug.assert(id.shard == shard);
            return id;
        }

        /// Resolve `id` to a live `*Value`, routing to `id.shard`'s table. Returns
        /// null if the shard is out of range, the slot is free, or the generation
        /// is stale. An id stamped for a foreign shard cannot resolve here.
        pub fn get(self: *Self, id: ClientId) ?*Value {
            const table = self.tablePtr(id.shard) catch return null;
            return table.get(id);
        }

        /// Free the slot named by `id` in `id.shard`'s table. Returns false if the
        /// shard is out of range or the id does not name a live slot.
        pub fn free(self: *Self, id: ClientId) bool {
            const table = self.tablePtr(id.shard) catch return false;
            return table.free(id);
        }

        /// Direct access to a shard's inner table for the owning reactor — e.g. to
        /// iterate live entries for a timeout sweep or fan-out. ONLY the reactor
        /// that owns `shard` may call this; cross-shard access is a contract
        /// violation (see the ownership note at the top of this file).
        pub fn shardTable(self: *Self, shard: u12) *InnerTable {
            std.debug.assert(@as(usize, shard) < self.shards.len);
            return &self.shards[shard];
        }

        /// Total live entries across every shard. O(num_shards).
        pub fn len(self: *const Self) usize {
            var total: usize = 0;
            for (self.shards) |*table| total += table.len();
            return total;
        }

        /// Live entries in a single shard. Returns 0 for an out-of-range shard.
        pub fn lenOfShard(self: *const Self, shard: u12) usize {
            if (@as(usize, shard) >= self.shards.len) return 0;
            return self.shards[shard].len();
        }

        fn tablePtr(self: *Self, shard: u12) ShardError!*InnerTable {
            if (@as(usize, shard) >= self.shards.len) return error.ShardOutOfRange;
            return &self.shards[shard];
        }
    };
}

const Client = client_model.Client;
const ShardedClients = ShardedTable(Client);

test "allocOn stamps the home shard and resolves via get" {
    // Arrange
    var table = try ShardedClients.init(std.testing.allocator, 4, 8);
    defer table.deinit();

    // Act
    const id0 = try table.allocOn(0, try Client.init(.{ .nick = "zero" }));
    const id2 = try table.allocOn(2, try Client.init(.{ .nick = "two" }));

    // Assert
    try std.testing.expectEqual(@as(u12, 0), id0.shard);
    try std.testing.expectEqual(@as(u12, 2), id2.shard);
    try std.testing.expect(table.get(id0).?.identity.nick.eql("zero"));
    try std.testing.expect(table.get(id2).?.identity.nick.eql("two"));
}

test "free removes an entry from its home shard" {
    // Arrange
    var table = try ShardedClients.init(std.testing.allocator, 2, 4);
    defer table.deinit();
    const id = try table.allocOn(1, try Client.init(.{ .nick = "doomed" }));
    try std.testing.expect(table.get(id) != null);

    // Act
    const freed = table.free(id);

    // Assert
    try std.testing.expect(freed);
    try std.testing.expectEqual(@as(?*Client, null), table.get(id));
}

test "lenOfShard counts per shard and len totals across shards" {
    // Arrange
    var table = try ShardedClients.init(std.testing.allocator, 3, 4);
    defer table.deinit();

    // Act
    _ = try table.allocOn(0, try Client.init(.{ .nick = "a" }));
    _ = try table.allocOn(2, try Client.init(.{ .nick = "b" }));
    _ = try table.allocOn(2, try Client.init(.{ .nick = "c" }));

    // Assert
    try std.testing.expectEqual(@as(usize, 1), table.lenOfShard(0));
    try std.testing.expectEqual(@as(usize, 0), table.lenOfShard(1));
    try std.testing.expectEqual(@as(usize, 2), table.lenOfShard(2));
    try std.testing.expectEqual(@as(usize, 3), table.len());
}

test "an id stamped for shard 3 does not resolve in shard 0's table" {
    // Arrange
    var table = try ShardedClients.init(std.testing.allocator, 4, 4);
    defer table.deinit();
    const id3 = try table.allocOn(3, try Client.init(.{ .nick = "remote" }));

    // Act: forge an id that points at the same slot/gen but claims shard 0.
    const forged = ClientId{ .shard = 0, .slot = id3.slot, .gen = id3.gen };

    // Assert: the genuine id resolves on its home shard; the forged one does not,
    // because shard 0's table rejects any id whose `.shard` is not its own.
    try std.testing.expect(table.get(id3) != null);
    try std.testing.expectEqual(@as(?*Client, null), table.get(forged));
}

test "out-of-range shard is reported, not panicked, on alloc and get" {
    // Arrange
    var table = try ShardedClients.init(std.testing.allocator, 2, 4);
    defer table.deinit();

    // Act / Assert
    try std.testing.expectError(error.ShardOutOfRange, table.allocOn(2, try Client.init(.{})));
    const bogus = ClientId{ .shard = 9, .slot = 0, .gen = 1 };
    try std.testing.expectEqual(@as(?*Client, null), table.get(bogus));
    try std.testing.expect(!table.free(bogus));
    try std.testing.expectEqual(@as(usize, 0), table.lenOfShard(9));
}

test "init rejects a zero shard count" {
    // Arrange / Act / Assert
    try std.testing.expectError(
        error.ShardCountInvalid,
        ShardedClients.init(std.testing.allocator, 0, 4),
    );
}
