//! Ringlane: the io_uring fast-path reactor backend (Linux). Portable
//! reactors land alongside this behind the same Reactor seam.
pub const ring = @import("ring.zig");

test {
    _ = ring;
}
