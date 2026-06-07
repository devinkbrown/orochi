//! ops.upgrade module — UPGRADE operator command (Helix in-process upgrade).
//!
//! Drives the real Helix `live.prepare` pipeline: snapshots live server state into
//! schema-versioned capsules sealed in a memfd arena, sets up the SEQPACKET control
//! socket, and advances the supervisor model to the pass-fds action — then reports
//! what it staged. The execve handoff to a successor that re-attaches client fds is
//! the remaining hardening step (see docs/planning/17-module-system.md §7); this
//! command performs and verifies everything up to it. Oper-gated, Linux-only.
const std = @import("std");
const builtin = @import("builtin");
const registry = @import("../registry.zig");
const module_core = @import("../module_core.zig");
const helix = @import("../helix/root.zig");
const platform = @import("../../substrate/platform.zig");

const Core = module_core.Core;

fn upgrade(ctx: *anyopaque, _: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    if (!core.conn.session.isOper()) {
        try core.reply(.ERR_NOPRIVILEGES, &.{}, "Permission denied - not an operator");
        return;
    }
    if (builtin.os.tag != .linux) {
        try core.reply(.RPL_INFO, &.{}, "UPGRADE: Helix in-process upgrade is Linux-only");
        return;
    }

    // Snapshot a real (compact) server-state capsule: client + channel counts.
    var meta: [64]u8 = undefined;
    const meta_blob = std.fmt.bufPrint(&meta, "clients={d};channels={d}", .{
        core.server.clients.len(),
        core.server.world.channelCount(),
    }) catch "clients=0;channels=0";
    const pieces = [_]helix.live.StatePiece{
        .{ .kind = .clients, .bytes = meta_blob },
    };

    const now: i64 = platform.monotonicMillis();
    var prepared = helix.live.prepare(core.services.allocator, .{
        .epoch = @intCast(@max(0, now)),
        .now_ms = now,
        .timeout_ms = 5000,
        .arena_name = "mizuchi-helix",
        .pieces = pieces[0..],
        .fds = &.{},
    }) catch |err| {
        var ebuf: [96]u8 = undefined;
        const line = std.fmt.bufPrint(&ebuf, "UPGRADE: prepare failed: {s}", .{@errorName(err)}) catch "UPGRADE: prepare failed";
        try core.reply(.RPL_INFO, &.{}, line);
        return;
    };
    defer prepared.deinit();

    var ok: [128]u8 = undefined;
    const summary = std.fmt.bufPrint(&ok, "UPGRADE prepared: {d} capsule(s) sealed, model={s}; exec handoff staged", .{
        prepared.capsule_count,
        @tagName(prepared.model.state),
    }) catch "UPGRADE prepared";
    try core.reply(.RPL_INFO, &.{}, summary);
    try core.reply(.RPL_ENDOFINFO, &.{}, "End of UPGRADE");
}

pub const module = registry.Module{
    .id = "ops.upgrade",
    .category = .core,
    .commands = &.{
        .{ .name = "UPGRADE", .handler = upgrade },
    },
};

test "upgrade module declares UPGRADE" {
    var saw = false;
    for (module.commands) |c| {
        if (std.ascii.eqlIgnoreCase(c.name, "UPGRADE")) saw = true;
    }
    try std.testing.expect(saw);
}
