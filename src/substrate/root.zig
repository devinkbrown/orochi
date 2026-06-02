//! mizuchi-substrate — reactor (Ringlane), allocators, lock-free queues,
//! data structures, LADON math (CRDT/HLC/vclock/Merkle), and the deterministic
//! simulation runtime (Deterministic Ocean). Skeleton; see planning/01.
pub const reactor = @import("reactor.zig");
pub const ladon = @import("ladon/root.zig");
pub const io = @import("io/root.zig");
pub const sketch = @import("sketch.zig");
pub const queue = @import("queue.zig");
pub const swim = @import("swim.zig");

pub const Reactor = reactor.Reactor;
pub const SystemReactor = reactor.SystemReactor;
pub const SimReactor = reactor.SimReactor;

test {
    _ = reactor;
    _ = ladon;
    _ = io;
    _ = sketch;
    _ = queue;
    _ = swim;
}
