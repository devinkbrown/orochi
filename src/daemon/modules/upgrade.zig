//! ops.upgrade module — UPGRADE operator command (Helix hot in-place upgrade).
//!
//! Thin dispatch wrapper: the real work lives in `LinuxServer.handleUpgrade`,
//! which serializes every registered session into a sealed memfd arena and
//! re-execs `--supervisor` preserving the listening socket + the arena (the
//! successor recovers the session state). Oper-gated, Linux-only.
const std = @import("std");
const registry = @import("../registry.zig");
const module_core = @import("../module_core.zig");

const Core = module_core.Core;

fn upgrade(ctx: *anyopaque, _: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    try core.server.handleUpgrade(core.conn);
}

pub const module = registry.Module{
    .id = "ops.upgrade",
    .category = .core,
    .commands = &.{
        .{ .name = "UPGRADE", .access = .oper, .handler = upgrade },
    },
};

test "upgrade module declares UPGRADE" {
    var saw = false;
    for (module.commands) |c| {
        if (std.ascii.eqlIgnoreCase(c.name, "UPGRADE")) {
            saw = true;
            try std.testing.expectEqual(registry.Access.oper, c.access);
        }
    }
    try std.testing.expect(saw);
}
