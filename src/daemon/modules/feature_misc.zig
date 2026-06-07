//! feature.misc module — identity (VHOST/PRIVS), content FILTER, media surface,
//! offline TEGAMI, and ACTIVITY presence. Thin thunks over existing LinuxServer
//! handlers. See 17-module-system.md.
const registry = @import("../registry.zig");
const Core = @import("../module_core.zig").Core;
const I = registry.CommandInvocation;

fn vhost(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleVhost(x.id, x.conn, x.parsed);
}
fn privs(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handlePrivs(x.conn);
}
fn filter(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleFilter(x.conn, x.parsed);
}
fn media(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleMedia(x.id, x.conn, x.parsed);
}
fn tegami(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleTegami(x.conn, x.parsed);
}
fn activity(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleActivity(x.id, x.conn, x.parsed);
}

pub const module = registry.Module{
    .id = "feature.misc",
    .commands = &.{
        .{ .name = "VHOST", .handler = vhost },
        .{ .name = "PRIVS", .handler = privs },
        .{ .name = "FILTER", .handler = filter },
        .{ .name = "MEDIA", .handler = media },
        .{ .name = "TEGAMI", .handler = tegami },
        .{ .name = "ACTIVITY", .handler = activity },
    },
};
