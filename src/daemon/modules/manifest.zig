//! SerpentRegistry module manifest — the single place modules are listed.
//!
//! Adding a module is one line here. A disabled module (deleted line) is
//! dead-code-eliminated. Duplicate commands/caps/modes/numerics across modules,
//! missing dependencies, and conflicts are all rejected at COMPILE TIME by
//! `registry.Registry` (it `@compileError`s) — never at runtime. See
//! `docs/planning/17-module-system.md` §2.
const registry = @import("../registry.zig");

const query_info = @import("query_info.zig");

/// The enabled module set. Order is load/dispatch order for ties.
pub const enabled = [_]registry.Module{
    query_info.module,
};

/// Comptime-assembled + comptime-validated live registry. Referencing `Live`
/// from the server forces the validation to run at build time.
pub const Live = registry.Registry(&enabled);
