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
fn geoipCmd(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleGeoip(x.conn, x.parsed);
}
/// SUMMON is intentionally disabled (RFC 2812 §4.5); reply 445.
fn summon(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.reply(.ERR_SUMMONDISABLED, &.{}, "SUMMON has been disabled");
}
/// A registered client's PONG heartbeat reply: accepted, no response.
fn pong(c: *anyopaque, _: I) anyerror!void {
    _ = c;
}

pub const module = registry.Module{
    .id = "feature.misc",
    .commands = &.{
        .{ .name = "VHOST", .handler = vhost },
        .{ .name = "PRIVS", .handler = privs },
        .{ .name = "FILTER", .handler = filter },
        .{ .name = "MEDIA", .feature = "media", .handler = media },
        .{ .name = "TEGAMI", .handler = tegami },
        .{ .name = "ACTIVITY", .handler = activity },
        .{ .name = "GEOIP", .min_params = 1, .access = .oper, .handler = geoipCmd, .summary = "GeoIP lookup of an IP (oper)" },
        .{ .name = "SUMMON", .access = .any, .handler = summon },
        .{ .name = "PONG", .access = .any, .handler = pong },
    },
};
