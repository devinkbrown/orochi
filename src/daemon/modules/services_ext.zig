//! services.ext module — extended channel/oper service commands.
//!
//! Thin thunks over existing LinuxServer handlers, following the strangler-fig
//! pattern (see 17-module-system.md). Migrating these out of the server's
//! residual `else if` chain makes them first-class registry commands: resolved
//! through the O(1) command map, validated for duplicates at comptime, and
//! surfaced by MODULES introspection.
const registry = @import("../registry.zig");
const Core = @import("../module_core.zig").Core;
const I = registry.CommandInvocation;

fn akick(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleAkick(x.id, x.conn, x.parsed);
}
fn resv(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleResv(x.conn, x.parsed);
}
fn forceAction(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleForceAction(x.id, x.conn, x.parsed);
}
fn clear(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleClear(x.id, x.conn, x.parsed);
}
fn tempmode(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleTempmode(x.id, x.conn, x.parsed);
}
fn clones(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleClones(x.conn);
}
fn seen(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSeen(x.conn, x.parsed);
}

pub const module = registry.Module{
    .id = "services.ext",
    .category = .service,
    .commands = &.{
        .{ .name = "AKICK", .handler = akick },
        .{ .name = "RESV", .handler = resv },
        .{ .name = "UNRESV", .handler = resv },
        .{ .name = "FORCEOP", .handler = forceAction },
        .{ .name = "FORCEDEOP", .handler = forceAction },
        .{ .name = "FORCEJOIN", .handler = forceAction },
        .{ .name = "FORCEPART", .handler = forceAction },
        .{ .name = "FORCETOPIC", .handler = forceAction },
        .{ .name = "CLEAR", .handler = clear },
        .{ .name = "TEMPMODE", .handler = tempmode },
        .{ .name = "CLONES", .handler = clones },
        .{ .name = "SEEN", .handler = seen },
    },
};
