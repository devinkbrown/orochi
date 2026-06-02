//! mizuchi-substrate — reactor (Ringlane), allocators, lock-free queues,
//! data structures, LADON math (CRDT/HLC/vclock/Merkle), and the deterministic
//! simulation runtime (Deterministic Ocean). Skeleton; see planning/01.
pub const reactor = @import("reactor.zig");

pub const Reactor = reactor.Reactor;
pub const SystemReactor = reactor.SystemReactor;
pub const SimReactor = reactor.SimReactor;
