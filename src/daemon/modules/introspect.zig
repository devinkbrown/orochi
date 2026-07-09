// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

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
const wasm_abi = @import("../../wasm/host/abi.zig");

const Core = module_core.Core;

fn modules(ctx: *anyopaque, _: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    if (!core.conn.session.isOper()) {
        try core.reply(.ERR_NOPRIVILEGES, &.{}, "Permission denied - not an operator");
        return;
    }

    try core.reply(.RPL_INFOSTART, &.{}, "SerpentRegistry - loaded modules");
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

/// COMMANDS — registry-driven command discovery. With no argument, list the
/// command names the caller may currently run (respecting access + feature
/// gates). With `COMMANDS <name>`, show that command's declarative metadata.
fn commands(ctx: *anyopaque, inv: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    const caps = registry.DispatchCaps{
        .registered = core.conn.session.registered(),
        .oper = core.conn.session.isOper(),
        .disabled_features = core.services.config.disabled_features,
    };

    // Detail form: COMMANDS <name>.
    if (inv.params.len >= 1 and inv.params[0].len != 0) {
        const want = inv.params[0];
        for (module_manifest.Live.commands) |entry| {
            if (!std.ascii.eqlIgnoreCase(entry.spec.name, want)) continue;
            const avail = registry.commandAvailable(entry.spec, caps);
            var buf: [320]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, "{s} [{s}] access={s}{s}{s} params>={d} {s}{s}", .{
                entry.spec.name,
                entry.module_id,
                entry.spec.access.token(),
                if (entry.spec.feature) |_| " feature=" else "",
                entry.spec.feature orelse "",
                entry.spec.min_params,
                if (avail) "" else "(unavailable) ",
                entry.spec.summary,
            }) catch return;
            try core.reply(.RPL_INFO, &.{}, line);
            try core.reply(.RPL_ENDOFINFO, &.{}, "End of COMMANDS");
            return;
        }
        try core.reply(.RPL_ENDOFINFO, &.{}, "No such command");
        return;
    }

    // List form: compact, several names per line, only what the caller can run.
    try core.reply(.RPL_INFOSTART, &.{}, "Commands available to you");
    var buf: [400]u8 = undefined;
    var used: usize = 0;
    for (module_manifest.Live.commands) |entry| {
        if (!registry.commandAvailable(entry.spec, caps)) continue;
        const name = entry.spec.name;
        if (used + name.len + 1 > buf.len) {
            try core.reply(.RPL_INFO, &.{}, buf[0..used]);
            used = 0;
        }
        @memcpy(buf[used..][0..name.len], name);
        used += name.len;
        buf[used] = ' ';
        used += 1;
    }
    if (used > 0) try core.reply(.RPL_INFO, &.{}, buf[0 .. used - 1]);
    try core.reply(.RPL_ENDOFINFO, &.{}, "End of COMMANDS");
}

/// OROWASM [STATUS|ABI|PLUGINS] — oper runtime view of the OroWasm host ABI,
/// resource budgets, allowed host capabilities, and loaded plugin registrations.
fn orowasm(ctx: *anyopaque, inv: registry.CommandInvocation) anyerror!void {
    const core = Core.from(ctx);
    const view = if (inv.params.len >= 1 and inv.params[0].len != 0) inv.params[0] else "STATUS";
    const info = core.server.wasm.runtimeInfo();

    var caps_buf: [128]u8 = undefined;
    const caps = info.allowed_caps.writeTokens(&caps_buf);
    var line: [512]u8 = undefined;

    if (std.ascii.eqlIgnoreCase(view, "STATUS")) {
        try core.reply(.RPL_INFOSTART, &.{}, "OroWasm runtime status");
        const status = std.fmt.bufPrint(&line, "plugins={d} commands={d} hooks={d} allowed_caps={s} disabled_plugins={d} blocked_loads={d} plugin_dir={s}", .{
            info.plugin_count,
            info.command_count,
            info.hook_count,
            if (caps.len == 0) "(none)" else caps,
            info.disabled_plugin_count,
            info.blocked_load_count,
            if (core.services.config.wasm_plugin_dir.len == 0) "(disabled)" else core.services.config.wasm_plugin_dir,
        }) catch return;
        try core.reply(.RPL_INFO, &.{}, status);
        const budgets = std.fmt.bufPrint(&line, "budgets max_plugin_bytes={d} max_memory_bytes={d} default_fuel={d}", .{
            info.max_plugin_bytes,
            info.max_memory_bytes,
            info.default_fuel,
        }) catch return;
        try core.reply(.RPL_INFO, &.{}, budgets);
        try core.reply(.RPL_ENDOFINFO, &.{}, "End of OROWASM");
        return;
    }

    if (std.ascii.eqlIgnoreCase(view, "ABI")) {
        try core.reply(.RPL_INFOSTART, &.{}, "OroWasm ABI");
        const schema = std.fmt.bufPrint(&line, "manifest_schema={d}.{d} host_functions={d} allowed_caps={s}", .{
            info.manifest_schema.major,
            info.manifest_schema.minor,
            info.host_function_count,
            if (caps.len == 0) "(none)" else caps,
        }) catch return;
        try core.reply(.RPL_INFO, &.{}, schema);
        for (wasm_abi.host_functions) |func| {
            const row = std.fmt.bufPrint(&line, "hostcall {s} v{d}.{d} cap={s}", .{
                func.name,
                func.version.major,
                func.version.minor,
                func.capability.token(),
            }) catch continue;
            try core.reply(.RPL_INFO, &.{}, row);
        }
        try core.reply(.RPL_ENDOFINFO, &.{}, "End of OROWASM");
        return;
    }

    if (std.ascii.eqlIgnoreCase(view, "PLUGINS")) {
        try core.reply(.RPL_INFOSTART, &.{}, "OroWasm plugins");
        var i: usize = 0;
        while (core.server.wasm.pluginSummary(i)) |plugin| : (i += 1) {
            var grant_buf: [128]u8 = undefined;
            const grants = plugin.grants.writeTokens(&grant_buf);
            const row = std.fmt.bufPrint(&line, "handle={d} name={s} commands={d} hooks={d} grants={s}", .{
                plugin.handle,
                plugin.name,
                plugin.command_count,
                plugin.hook_count,
                if (grants.len == 0) "(none)" else grants,
            }) catch continue;
            try core.reply(.RPL_INFO, &.{}, row);
        }
        if (i == 0) try core.reply(.RPL_INFO, &.{}, "no plugins loaded");
        try core.reply(.RPL_ENDOFINFO, &.{}, "End of OROWASM");
        return;
    }

    try core.reply(.RPL_ENDOFINFO, &.{}, "Usage: OROWASM [STATUS|ABI|PLUGINS]");
}

pub const module = registry.Module{
    .id = "diag.introspect",
    .category = .diagnostic,
    .commands = &.{
        .{ .name = "MODULES", .handler = modules, .summary = "list loaded registry modules" },
        .{ .name = "MODLIST", .handler = modules, .summary = "alias of MODULES" },
        .{ .name = "COMMANDS", .access = .any, .handler = commands, .summary = "discover commands you can run" },
        .{ .name = "OROWASM", .access = .oper, .handler = orowasm, .summary = "inspect OroWasm ABI, budgets, and plugins" },
    },
};

test "introspect module declares MODULES and OROWASM, and the registry is visible" {
    var saw_modules = false;
    var saw_orowasm = false;
    for (module.commands) |c| {
        if (std.ascii.eqlIgnoreCase(c.name, "MODULES")) saw_modules = true;
        if (std.ascii.eqlIgnoreCase(c.name, "OROWASM")) saw_orowasm = true;
    }
    try std.testing.expect(saw_modules);
    try std.testing.expect(saw_orowasm);
    try std.testing.expect(module_manifest.enabled.len >= 1);
}
