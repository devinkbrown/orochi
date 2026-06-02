# Zig 0.16 notes + worker integration rules (READ FIRST)

Mizuchi targets **Zig 0.16.0**. The std library changed a lot vs older Zig; code
written from memory of 0.11–0.14 will NOT compile. Verify everything by compiling.

## Confirmed 0.16 API facts (hit during scaffolding)
- **No `std.time.milliTimestamp` / `nanoTimestamp` / `Timer` / `Instant`.** Wall/monotonic
  clock helpers were removed from `std.time` (only unit constants + `epoch` remain).
  For monotonic time use:
  ```zig
  var ts: std.os.linux.timespec = undefined; // fields: sec: isize, nsec: isize
  _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts);
  const ms = @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000_000);
  ```
- **No `std.testing.refAllDeclsRecursive`.** Use `std.testing.refAllDecls(@This())` plus
  explicit `_ = @import("...");` to pull in sibling tests.
- **`build.zig` shape:** executables use `.root_module = b.createModule(.{ .root_source_file,
  .target, .optimize, .imports })`; `b.addModule(name, .{ .root_source_file, .target })`;
  tests use `b.addTest(.{ .root_module = ... })`. (See the repo's build.zig — do not edit it.)
- Console output: use `std.debug.print(fmt, args)` (goes to stderr). Avoid the old
  `std.io.getStdOut().writer()` API; the std.Io/Writer surface was overhauled — if you
  need real I/O, route it through the Reactor seam, not std directly.
- `@typeInfo` tags are lowercase in 0.16 (e.g. `.@"struct"`, `.@"enum"`, `.pointer`,
  `.int`). Verify against `/usr/lib/zig/std/builtin.zig` if you use them.
- When unsure about ANY std API, grep `/usr/lib/zig/std/` and then compile.

## Hard verification requirement
Your deliverable is not done until it COMPILES and its tests PASS under 0.16:
```
zig test path/to/your_file.zig
```
Each file you create MUST be self-contained (import only `std`) so it can be tested in
isolation. Iterate until green. Do not hand back code you have not compiled.

## Integration rules (do not break the build for others)
- Create ONLY the file(s) you are assigned, at the exact path given. Add new files; do
  not delete.
- **DO NOT edit** `src/root.zig`, `build.zig`, `build.zig.zon`, or any package root
  (`src/*/root.zig`). The orchestrator (Claude) wires new files into the package roots
  during integration. If you wire them yourself you create merge conflicts.
- Put `test { ... }` blocks in your file covering the core behavior (aim high; this is
  a correctness-critical systems project).
- Match the style of `src/substrate/reactor.zig`: `//!` module doc comment, `//` doc
  comments on public decls, PascalCase types, camelCase functions, snake_case fields/vars.
- No `unreachable`/`@panic` on attacker-reachable input; handle errors explicitly.
- Keep files focused (<800 lines). Prefer caller-provided buffers/slices over hidden
  allocation in hot-path code.

## Where the design lives
- `docs/planning/00-architecture.md` — canonical design + invention glossary (authority).
- `docs/planning/01-substrate.md` .. `05-innovation.md` — detailed per-area design.
- `docs/BRIEF.md` — mission + locked decisions.
