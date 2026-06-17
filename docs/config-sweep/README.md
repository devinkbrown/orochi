# Config hardcoded-value sweep — backlog

A maximal survey (2026-06-07) of operational/tuning constants to lift into the
TOML config (`config_format.zig` / `proto/toml.zig`). ~343 candidates across 7
subsystems. Each `<subsystem>.md` is a `[section]`-grouped table:
`file:line · symbol · current value · what it controls · proposed key · type ·
default · range`.

## Status
- **Engine overhaul (done):** real TOML v1.0 (`proto/toml.zig`) is the single
  config parser; the three legacy custom parsers are consolidated to one.
- **Threaded so far:** server-core runtime knobs — `[limits].sweep_interval`,
  `[limits].nick_delay`, `[reputation].*`, `[io].ring_entries`, and connection
  classes `[class.<name>]` (per-connection resource and admission policy).
- **Remaining:** the rest of these tables, in subsystem waves. Notes:
  - Many subsystems already expose a `Config` struct → wire it from TOML at the
    construction site.
  - **Comptime-bound** values (`[N]u8` buffer widths, `Session(N)`, reorder
    windows, `sasl_decode_cap`) need a comptime→runtime/allocation rework, not a
    drop-in knob — lift these deliberately.
  - `isupport.zig` `default_tokens` is the single authoritative IRC limits table;
    feed `[limits]`/`[ircv3]` from it once, not per-module.
