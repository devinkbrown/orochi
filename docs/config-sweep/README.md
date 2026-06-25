# Config hardcoded-value sweep — backlog

*Survey of operational and tuning constants to lift from source into the TOML config.*

This sweep (2026-06-07) catalogs roughly 343 hardcoded candidates across seven
subsystems, targeting the TOML config layer (`config_format.zig` /
`proto/toml.zig`). Each `<subsystem>.md` file is a `[section]`-grouped table with
these columns:

`file:line` · `symbol` · `current value` · `what it controls` · `proposed key` ·
`type` · `default` · `range`.

## Status

- **Engine overhaul (done).** Real TOML v1.0 (`proto/toml.zig`) is now the single
  config parser; the three legacy custom parsers are consolidated into one.
- **Threaded so far.** Server-core runtime knobs: `[limits].sweep_interval`,
  `[limits].nick_delay`, `[reputation].*`, `[io].ring_entries`, and connection
  classes `[class.<name>]` (per-connection resource and admission policy).
- **Remaining.** The rest of these tables, lifted in subsystem waves. Notes:
  - Many subsystems already expose a `Config` struct — wire it from TOML at the
    construction site.
  - **Comptime-bound** values (`[N]u8` buffer widths, `Session(N)`, reorder
    windows, `sasl_decode_cap`) need a comptime-to-runtime or allocation rework,
    not a drop-in knob. Lift these deliberately.
  - `isupport.zig` `default_tokens` is the single authoritative IRC limits table;
    feed `[limits]` and `[ircv3]` from it once, not per-module.
