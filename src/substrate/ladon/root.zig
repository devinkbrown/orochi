//! LADON math substrate: logical clocks, delta-state CRDTs, and Merkle
//! anti-entropy — the building blocks of the LADON mesh state model.
pub const clock = @import("clock.zig");
pub const crdt = @import("crdt.zig");
pub const merkle = @import("merkle.zig");
pub const state = @import("state.zig");
pub const anti_entropy = @import("anti_entropy.zig");

test {
    _ = clock;
    _ = crdt;
    _ = merkle;
    _ = state;
    _ = anti_entropy;
}
