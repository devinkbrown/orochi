// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! WASM build root for the browser transport shim (#32).
//!
//! Rooting the wasm module at `src/` (rather than at `src/wasm/`) lets the shim
//! import the std-only `irc_line` parser by the same relative path the native
//! test build uses, so there is one source of truth and no per-target import
//! wiring. Only the reachable files (transport_shim -> browser_transport ->
//! irc_line, all std-only) are compiled, so the freestanding target stays clean.
//!
//! The `export fn`s live in transport_shim.zig; referencing it here forces their
//! analysis, and `-rdynamic` keeps them in the final module.
comptime {
    _ = @import("wasm/transport_shim.zig");
}
