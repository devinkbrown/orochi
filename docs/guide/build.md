# Build guide

*Build, test, and cross-compile the Orochi daemon with Zig.*

Orochi builds with Zig's build system and has no package dependencies in `build.zig.zon` (`build.zig.zon:34`). Linux builds do not link libc; macOS and BSD targets link libc only for the platform syscalls that require it (`build.zig:40`, `build.zig:43`).

## Requirements

- Zig `0.17.0-dev.1282+c0f9b51d8` or newer as declared by `build.zig.zon` (`build.zig.zon:34`).
- A 64-bit daemon target. `build.zig` rejects 32-bit daemon builds at configure time (`build.zig:20`, `build.zig:24`).

## Common targets

| Command | What it does | Source |
|---|---|---|
| `zig build` | Builds and installs `zig-out/bin/orochi`. | `build.zig` |
| `zig build run -- <config.toml>` | Builds, installs, then runs the daemon with forwarded args. | `build.zig` |
| `zig build test` | Runs module tests and executable-root tests. | `build.zig` |
| `zig build test -Dtest-filter=<text>` | Runs tests whose names contain the filter. | `build.zig` |
| `zig build test-mod -Dtest-filter=<text>` | Runs only the library/module test artifact with the optional filter. | `build.zig` |
| `zig build test-exe -Dtest-filter=<text>` | Runs only the executable-root test artifact with the optional filter. | `build.zig` |
| `zig build test-tls` | Runs focused Yoroi TLS/mTLS/ECH/RPK/DC tests. | `build.zig` |
| `zig build test-server` | Runs focused daemon/server integration and auth tests. | `build.zig` |
| `zig build test-config` | Runs focused TOML/config parsing and boot-projection tests. | `build.zig` |
| `zig build test-smoke` | Runs `check` plus focused TLS/server/config suites. | `build.zig` |
| `zig build all-checks` | Runs deterministic pre-push checks: `check`, full tests, bounded fuzz replay, and BoGo shim self-tests. | `build.zig` |
| `zig build test-verbose` | Runs full tests with per-test progress output. | `build.zig` |
| `zig build all-checks-verbose` | Runs deterministic pre-push checks with per-test progress output for the full suite. | `build.zig` |
| `zig build check` | Type-checks the daemon without emitting a binary. | `build.zig` |
| `zig build wasm` | Builds browser-facing KaguraVox/KaguraVis codec and transport WASM modules. | `build.zig` |
| `zig build release` | Builds an optimized stripped daemon with `ReleaseFast`. | `build.zig` |

`-Dtest-filter=<text>` is a build option. Do not pass `-- --test-filter`; that
does not configure the build graph and can run far more than intended. See the
[testing guide](testing.md) for the recommended lanes.

## Cross targets

Pass `-Dtarget=<triple>` to choose a target; the build script uses standard target options (`build.zig:10`, `build.zig:14`).

For example:

```sh
zig build -Dtarget=x86_64-linux
zig build -Dtarget=aarch64-linux -Doptimize=ReleaseSafe
zig build check -Dtarget=x86_64-linux
```

The daemon target must be 64-bit. The `wasm` step is the deliberate `wasm32-freestanding` exception for browser codec and transport artifacts, not for the daemon (`build.zig:176`, `build.zig:179`).

## Optimization

Use Zig's standard `-Doptimize=` modes. Debug builds keep symbols; optimized daemon builds strip debug info (`build.zig:15`, `build.zig:31`).
