//! ircx module — IRCX protocol command family (CREATE lives in channel.ops;
//! this covers IRCX/ISIRCX/DATA/REQUEST/REPLY/WHISPER/PROP/ACCESS/EVENT/MODEX/
//! LISTX). Thin thunks over existing LinuxServer handlers. See 17-module-system.md.
const registry = @import("../registry.zig");
const Core = @import("../module_core.zig").Core;
const I = registry.CommandInvocation;

fn ircxOn(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleIrcx(x.conn, true);
}
fn ircxQuery(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleIrcx(x.conn, false);
}
fn data(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleData(x.id, x.conn, x.parsed);
}
fn whisper(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleWhisper(x.id, x.conn, x.parsed);
}
fn prop(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleProp(x.id, x.conn, x.parsed);
}
fn access(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleAccess(x.id, x.conn, x.parsed);
}
fn event(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleEvent(x.conn, x.parsed);
}
fn modex(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleModex(x.id, x.conn, x.parsed);
}
fn listx(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleListx(x.conn, x.parsed);
}

pub const module = registry.Module{
    .id = "ircx",
    .commands = &.{
        .{ .name = "IRCX", .handler = ircxOn },
        .{ .name = "ISIRCX", .handler = ircxQuery },
        .{ .name = "DATA", .handler = data },
        .{ .name = "REQUEST", .handler = data },
        .{ .name = "REPLY", .handler = data },
        .{ .name = "WHISPER", .handler = whisper },
        .{ .name = "PROP", .handler = prop },
        .{ .name = "ACCESS", .handler = access },
        .{ .name = "EVENT", .handler = event },
        .{ .name = "MODEX", .handler = modex },
        .{ .name = "LISTX", .handler = listx },
    },
};
