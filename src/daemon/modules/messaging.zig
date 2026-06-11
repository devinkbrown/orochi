//! messaging module — PRIVMSG/NOTICE/TAGMSG and IRCv3 message-layer commands.
//! Thin thunks over existing LinuxServer handlers. See 17-module-system.md.
const registry = @import("../registry.zig");
const Core = @import("../module_core.zig").Core;
const I = registry.CommandInvocation;

fn privmsg(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleMessage(x.id, x.conn, x.parsed, "PRIVMSG");
}
fn notice(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleMessage(x.id, x.conn, x.parsed, "NOTICE");
}
fn tagmsg(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleTagmsg(x.id, x.conn, x.parsed);
}
fn redact(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleRedact(x.id, x.conn, x.parsed);
}
fn edit(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleEdit(x.id, x.conn, x.line);
}
fn chathistory(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleChathistory(x.id, x.conn, x.line);
}
fn markread(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleMarkread(x.conn, x.parsed);
}
fn metadata(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleMetadata(x.id, x.conn, x.parsed);
}
fn monitor(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleMonitor(x.id, x.conn, x.parsed);
}
fn silence(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSilence(x.conn, x.parsed);
}

pub const module = registry.Module{
    .id = "messaging",
    .commands = &.{
        .{ .name = "PRIVMSG", .handler = privmsg },
        .{ .name = "NOTICE", .handler = notice },
        .{ .name = "TAGMSG", .handler = tagmsg },
        .{ .name = "REDACT", .handler = redact },
        .{ .name = "EDIT", .handler = edit },
        .{ .name = "CHATHISTORY", .handler = chathistory },
        .{ .name = "MARKREAD", .handler = markread },
        .{ .name = "METADATA", .handler = metadata },
        .{ .name = "MONITOR", .handler = monitor },
        .{ .name = "SILENCE", .handler = silence },
    },
};
