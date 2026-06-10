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
fn mesh(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleMesh(x.conn, x.parsed);
}

pub const module = registry.Module{
    .id = "oper.security",
    .commands = &.{
        // OPER is how a client *becomes* an operator; STATS and USERIP are not
        // operator-gated here. The rest require operator authority, enforced
        // declaratively by the registry (access=.oper).
        .{ .name = "OPER", .handler = oper },
        .{ .name = "REHASH", .access = .oper, .handler = rehash },
        .{ .name = "KILL", .access = .oper, .handler = kill },
        .{ .name = "CLOSE", .access = .oper, .handler = close },
        .{ .name = "DRAIN", .access = .oper, .handler = drain },
        .{ .name = "UNREJECT", .access = .oper, .handler = unreject },
        .{ .name = "WARD", .access = .oper, .handler = ward },
        .{ .name = "SHUN", .access = .oper, .handler = shun },
        .{ .name = "UNSHUN", .access = .oper, .handler = unshun },
        .{ .name = "GLOBAL", .access = .oper, .handler = global },
        .{ .name = "OPERMOTD", .access = .oper, .handler = operMotd },
        .{ .name = "DIE", .access = .oper, .handler = die },
        .{ .name = "RESTART", .access = .oper, .handler = die },
        .{ .name = "CONNECT", .access = .oper, .handler = connect },
        .{ .name = "SQUIT", .access = .oper, .handler = squit },
        .{ .name = "TRACE", .access = .oper, .handler = trace },
        .{ .name = "ETRACE", .access = .oper, .handler = etrace },
        .{ .name = "STATS", .handler = stats },
        .{ .name = "TESTLINE", .access = .oper, .handler = testline },
        .{ .name = "TESTMASK", .access = .oper, .handler = testmask },
        .{ .name = "USERIP", .handler = userip },
        .{ .name = "DEBUG", .access = .oper, .handler = debug },
        .{ .name = "MESH", .access = .oper, .handler = mesh, .summary = "mesh peer/link health (NETSTAT)" },
        .{ .name = "NETSTAT", .access = .oper, .handler = mesh, .summary = "alias of MESH" },
    },
};
