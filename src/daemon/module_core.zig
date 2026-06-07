//! Module capability handle — the typed context every SerpentRegistry module
//! receives. See `docs/planning/17-module-system.md`.
//!
//! `Core` is the per-invocation context (current client + parsed line + a handle
//! to the live server). `Services` is the long-lived, host-owned capability set
//! a module is allowed to touch. We deliberately split them: `Core` is cheap to
//! build per command; `Services` outlives every connection and survives upgrades.
//!
//! Migration note (strangler-fig): `Core.server` is the escape hatch so a module
//! handler can call an existing `LinuxServer` method verbatim while a command
//! family is being extracted. As families migrate, logic moves behind the narrow
//! `Core`/`Services` helpers and the raw `server` reach-through shrinks.
const std = @import("std");
const server = @import("server.zig");
const client_model = @import("client.zig");

/// Long-lived, host-owned capabilities. Borrowed by `Core`; never owned by a
/// module. The host allocator (not a module-created one) is the cure for the
/// classic stale-allocator-vtable crash on reload/upgrade.
pub const Services = struct {
    allocator: std.mem.Allocator,
    config: *const server.Config,
};

/// Per-command-invocation context passed to every module command handler as the
/// erased `*anyopaque` ctx; handlers recover it with `Core.from(ctx)`.
pub const Core = struct {
    services: Services,
    server: *server.LinuxServer,
    id: client_model.ClientId,
    conn: *server.ConnState,
    parsed: *const server.ParsedLine,
    line: []const u8,

    /// Recover the typed context from the registry's erased handler ctx.
    pub fn from(ctx: *anyopaque) *Core {
        return @ptrCast(@alignCast(ctx));
    }

    /// Parameters of the current command (`[]const []const u8`).
    pub fn params(self: *const Core) []const []const u8 {
        return self.parsed.paramSlice();
    }
};
