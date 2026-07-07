// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! webhook module — the `WEBHOOK` channel-admin command.
//!
//! Manages Discord-compatible incoming webhook bindings
//! (`CREATE <#channel> [name]` | `LIST <#channel>` | `DELETE <id>`). Gated by
//! the `"webhook"` config feature: when `[webhook] enabled` is unset the command
//! returns 421 (invisible), so a webhook-off daemon is byte-identical. The thin
//! thunk delegates to the `LinuxServer.handleWebhook` body; channel-operator
//! gating happens inside that handler. See webhook.zig / webhook_http.zig.
const registry = @import("../registry.zig");
const Core = @import("../module_core.zig").Core;
const I = registry.CommandInvocation;

const webhook_feature = "webhook";

fn webhook(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleWebhook(x.id, x.conn, x.parsed);
}

pub const WEBHOOK_spec = registry.CommandSpec{
    .name = "WEBHOOK",
    .min_params = 1,
    .feature = webhook_feature,
    .handler = webhook,
    .summary = "manage channel incoming webhooks (CREATE <#channel> [name] | LIST <#channel> | DELETE <id>)",
};

pub const module = registry.Module{
    .id = "webhook",
    .commands = &.{
        WEBHOOK_spec,
    },
};
