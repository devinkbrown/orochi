//! channel.ops module — channel membership and moderation commands.
//! Thin thunks delegating to existing LinuxServer handler bodies (behavior
//! preserved; routing moved off the if-chain). See 17-module-system.md.
const registry = @import("../registry.zig");
const Core = @import("../module_core.zig").Core;
const I = registry.CommandInvocation;

fn join(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleJoin(x.id, x.conn, x.parsed);
}
fn part(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handlePart(x.id, x.conn, x.parsed);
}
fn names(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleNames(x.conn, x.parsed);
}
fn mode(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleMode(x.id, x.conn, x.parsed);
}
fn kick(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleKick(x.id, x.conn, x.parsed);
}
fn invite(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleInvite(x.id, x.conn, x.parsed);
}
fn topic(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleTopic(x.id, x.conn, x.parsed);
}
fn knock(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleKnock(x.id, x.conn, x.parsed);
}
fn create(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleCreate(x.id, x.conn, x.parsed);
}

pub const module = registry.Module{
    .id = "channel.ops",
    .commands = &.{
        .{ .name = "JOIN", .handler = join },
        .{ .name = "PART", .handler = part },
        .{ .name = "NAMES", .handler = names },
        .{ .name = "MODE", .handler = mode },
        .{ .name = "KICK", .handler = kick },
        .{ .name = "INVITE", .handler = invite },
        .{ .name = "TOPIC", .handler = topic },
        .{ .name = "KNOCK", .handler = knock },
        .{ .name = "CREATE", .handler = create },
    },
};
