// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! user.query module — user-facing query + identity commands (WHOIS/WHO/LIST/
//! NICK/AWAY/QUIT/…). Thin thunks over existing LinuxServer handlers.
//! See 17-module-system.md.
const registry = @import("../registry.zig");
const Core = @import("../module_core.zig").Core;
const I = registry.CommandInvocation;

fn ison(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleIson(x.conn, x.parsed);
}
fn userhost(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleUserhost(x.conn, x.parsed);
}
fn whois(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleWhois(x.conn, x.parsed);
}
fn list(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleList(x.conn, x.parsed);
}
fn who(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleWho(x.conn, x.parsed);
}
fn whowas(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleWhowas(x.conn, x.parsed);
}
fn away(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleAway(x.id, x.conn, x.parsed);
}
fn setname(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSetname(x.id, x.conn, x.parsed);
}
fn nick(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleNickChange(x.id, x.conn, x.parsed);
}
fn quit(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleQuit(x.id, x.conn, x.parsed);
}
fn accept(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleAcceptCmd(x.conn, x.parsed);
}
fn help(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleHelp(x.conn, x.parsed);
}
fn autojoin(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleAutojoin(x.conn, x.parsed);
}
fn group(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleGroup(x.conn, x.parsed);
}
fn welcome(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleWelcome(x.conn, x.parsed);
}

pub const module = registry.Module{
    .id = "user.query",
    .commands = &.{
        .{ .name = "ISON", .handler = ison },
        .{ .name = "USERHOST", .handler = userhost },
        .{ .name = "WHOIS", .handler = whois },
        .{ .name = "LIST", .handler = list },
        .{ .name = "WHO", .handler = who },
        .{ .name = "WHOWAS", .handler = whowas },
        .{ .name = "AWAY", .handler = away },
        .{ .name = "SETNAME", .handler = setname },
        .{ .name = "NICK", .handler = nick },
        .{ .name = "QUIT", .handler = quit },
        .{ .name = "ACCEPT", .handler = accept },
        .{ .name = "HELP", .handler = help },
        .{ .name = "HELPOP", .handler = help },
        .{ .name = "AUTOJOIN", .handler = autojoin },
        .{ .name = "GROUP", .handler = group },
        .{ .name = "WELCOME", .handler = welcome },
    },
};
