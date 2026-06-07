//! Helix Upgrade subsystem root.

const std = @import("std");

// Core upgrade transport + supervisor.
pub const attest = @import("attest.zig");
pub const capsule = @import("capsule.zig");
pub const handoff = @import("handoff.zig");
pub const live = @import("live.zig");
pub const supervisor = @import("supervisor.zig");
pub const conduit = @import("conduit.zig");

// State-migration capsules (one schema per resumable subsystem).
pub const conn_capsule = @import("conn_capsule.zig");
pub const world_capsule = @import("world_capsule.zig");
pub const account_capsule = @import("account_capsule.zig");
pub const listener_capsule = @import("listener_capsule.zig");
pub const session_capsule = @import("session_capsule.zig");
pub const monitor_capsule = @import("monitor_capsule.zig");
pub const metadata_capsule = @import("metadata_capsule.zig");
pub const bouncer_buffer_capsule = @import("bouncer_buffer_capsule.zig");
pub const read_marker_capsule = @import("read_marker_capsule.zig");
pub const chathistory_cursor_capsule = @import("chathistory_cursor_capsule.zig");
pub const away_capsule = @import("away_capsule.zig");
pub const upgrade_manifest = @import("upgrade_manifest.zig");

// Successor-side planners + deterministic self-tests.
pub const resume_plan = @import("resume_plan.zig");
pub const session_resume_plan = @import("session_resume_plan.zig");
pub const upgrade_dst = @import("upgrade_dst.zig");
pub const session_migration_dst = @import("session_migration_dst.zig");

test {
    std.testing.refAllDecls(@This());
}
