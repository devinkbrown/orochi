//! accounts module — account/services command family (register, identify,
//! channel registration, ghost, multi-session). Thin thunks over existing
//! LinuxServer handlers. See 17-module-system.md.
const registry = @import("../registry.zig");
const Core = @import("../module_core.zig").Core;
const I = registry.CommandInvocation;

fn register(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleRegister(x.conn, x.parsed);
}
fn verify(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleVerify(x.conn, x.parsed);
}
fn identify(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleIdentify(x.conn, x.parsed);
}
fn logout(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleLogout(x.id, x.conn);
}
fn drop(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleDrop(x.conn, x.parsed);
}
fn accountInfo(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleAccountInfo(x.conn, x.parsed);
}
fn saslInfo(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSaslInfo(x.conn);
}
fn accountSet(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleAccountSet(x.conn, x.parsed);
}
fn ghost(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleGhost(x.conn, x.parsed);
}
fn channel(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleChannel(x.conn, x.parsed);
}
fn session(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSession(x.id, x.conn, x.parsed);
}

pub const module = registry.Module{
    .id = "accounts",
    .commands = &.{
        .{ .name = "REGISTER", .handler = register },
        .{ .name = "VERIFY", .handler = verify },
        .{ .name = "IDENTIFY", .handler = identify },
        .{ .name = "LOGOUT", .handler = logout },
        .{ .name = "DROP", .handler = drop },
        .{ .name = "ACCOUNTINFO", .handler = accountInfo },
        .{ .name = "SASLINFO", .handler = saslInfo },
        .{ .name = "ACCOUNTSET", .handler = accountSet },
        .{ .name = "GHOST", .handler = ghost },
        .{ .name = "CHANNEL", .handler = channel },
        .{ .name = "CS", .handler = channel },
        .{ .name = "SESSION", .handler = session },
    },
};
