//! Mizuchi library root — re-exports the package namespaces.
//! See docs/planning/00-architecture.md for the canonical design.
const std = @import("std");

pub const version = "0.0.1-dev";

pub const substrate = @import("substrate/root.zig");
pub const crypto = @import("crypto/root.zig");
pub const proto = @import("proto/root.zig");
pub const daemon = @import("daemon/root.zig");

test {
    // 0.16 dropped refAllDeclsRecursive; reference each package so its tests run.
    std.testing.refAllDecls(@This());
    _ = substrate.reactor;
    _ = crypto.secret;
    _ = proto;
    _ = daemon;
}
