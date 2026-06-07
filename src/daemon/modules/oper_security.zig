//! oper.security module — operator tooling + network security/moderation
//! commands. Thin thunks over existing LinuxServer handlers. See 17-module-system.md.
const registry = @import("../registry.zig");
const Core = @import("../module_core.zig").Core;
const I = registry.CommandInvocation;

fn oper(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleOper(x.conn, x.parsed);
}
fn rehash(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleRehash(x.conn);
}
fn kill(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleKill(x.conn, x.parsed);
}
fn close(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleClose(x.conn);
}
fn drain(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleDrain(x.conn, x.parsed);
}
fn unreject(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleUnreject(x.conn, x.parsed);
}
fn ward(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleWard(x.conn, x.parsed);
}
fn shun(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleShun(x.conn, x.parsed, true);
}
fn unshun(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleShun(x.conn, x.parsed, false);
}
fn global(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleGlobal(x.id, x.conn, x.parsed);
}
fn operMotd(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleOperMotd(x.conn, x.parsed);
}
fn die(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleDie(x.conn, x.parsed.command);
}
fn connect(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleConnectCmd(x.conn, x.parsed);
}
fn squit(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSquit(x.conn, x.parsed);
}
fn trace(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleTrace(x.conn);
}
fn etrace(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleEtrace(x.conn);
}
fn stats(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleStats(x.conn, x.parsed);
}
fn testline(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleTestline(x.conn, x.parsed);
}
fn testmask(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleTestmask(x.conn, x.parsed);
}
fn userip(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleUserip(x.conn, x.parsed);
}
fn debug(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleDebug(x.conn);
}

pub const module = registry.Module{
    .id = "oper.security",
    .commands = &.{
        .{ .name = "OPER", .handler = oper },
        .{ .name = "REHASH", .handler = rehash },
        .{ .name = "KILL", .handler = kill },
        .{ .name = "CLOSE", .handler = close },
        .{ .name = "DRAIN", .handler = drain },
        .{ .name = "UNREJECT", .handler = unreject },
        .{ .name = "WARD", .handler = ward },
        .{ .name = "SHUN", .handler = shun },
        .{ .name = "UNSHUN", .handler = unshun },
        .{ .name = "GLOBAL", .handler = global },
        .{ .name = "OPERMOTD", .handler = operMotd },
        .{ .name = "DIE", .handler = die },
        .{ .name = "RESTART", .handler = die },
        .{ .name = "CONNECT", .handler = connect },
        .{ .name = "SQUIT", .handler = squit },
        .{ .name = "TRACE", .handler = trace },
        .{ .name = "ETRACE", .handler = etrace },
        .{ .name = "STATS", .handler = stats },
        .{ .name = "TESTLINE", .handler = testline },
        .{ .name = "TESTMASK", .handler = testmask },
        .{ .name = "USERIP", .handler = userip },
        .{ .name = "DEBUG", .handler = debug },
    },
};
