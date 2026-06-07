//! diag.introspect module — MODULES / MODLIST operator introspection.
//!
//! Lists what the comptime SerpentRegistry assembled (loaded modules + per-module
//! command/cap/hook counts + totals), so an operator can see the live module
//! topology. Reads the comptime tables on `module_manifest.Live`. Oper-gated.
//! See docs/planning/17-module-system.md.
const std = @import("std");
const registry = @import("../registry.zig");
const module_core = @import("../module_core.zig");
const module_manifest = @import("manifest.zig");

const Core = module_core.Core;

fn modules(ctx: *anyopaque, _: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    if (!core.conn.session.isOper()) {
        try core.reply(.ERR_NOPRIVILEGES, &.{}, "Permission denied - not an operator");
        return;
    }

    try core.reply(.RPL_INFOSTART, &.{}, "SerpentRegistry — loaded modules");
    var buf: [256]u8 = undefined;
    inline for (module_manifest.enabled) |m| {
        const line = std.fmt.bufPrint(&buf, "{s}: {d} cmds, {d} caps, {d} hooks", .{
            m.id,
            m.commands.len,
            m.caps.len,
            m.hooks.len,
        }) catch "module (format error)";
        try core.reply(.RPL_INFO, &.{}, line);
    }
    const summary = std.fmt.bufPrint(&buf, "{d} modules, {d} commands total", .{
        module_manifest.enabled.len,
        module_manifest.Live.commands.len,
    }) catch "summary (format error)";
    try core.reply(.RPL_ENDOFINFO, &.{}, summary);
}

pub const module = registry.Module{
    .id = "diag.introspect",
    .category = .diagnostic,
    .commands = &.{
        .{ .name = "MODULES", .handler = modules },
        .{ .name = "MODLIST", .handler = modules },
    },
};

test "introspect module declares MODULES and the registry is visible" {
    var saw_modules = false;
    for (module.commands) |c| {
        if (std.ascii.eqlIgnoreCase(c.name, "MODULES")) saw_modules = true;
    }
    try std.testing.expect(saw_modules);
    try std.testing.expect(module_manifest.enabled.len >= 1);
}
