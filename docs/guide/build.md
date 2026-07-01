# Build guide

*Build, test, and cross-compile the Orochi daemon with Zig.*

Orochi builds with Zig's build system and has no package dependencies in `build.zig.zon` (`build.zig.zon:34`). Linux builds do not link libc; macOS and BSD targets link libc only for the platform syscalls that require it (`build.zig:40`, `build.zig:43`).

## Requirements

- Zig `0.16.0` or newer as declared by `build.zig.zon` (`build.zig.zon:28`).
- A 64-bit daemon target. `build.zig` rejects 32-bit daemon builds at configure time (`build.zig:20`, `build.zig:24`).

## Common targets

| Command | What it does | Source |
|---|---|---|
| `zig build` | Builds and installs `zig-out/bin/orochi`. | `build.zig:87`, `build.zig:119` |
| `zig build run -- <config.toml>` | Builds, installs, then runs the daemon with forwarded args. | `build.zig:126`, `build.zig:143` |
| `zig build test` | Runs module tests and executable-root tests. | `build.zig:150`, `build.zig:161`, `build.zig:172` |
| `zig build test -Dtest-filter=<text>` | Runs tests whose names contain the filter. | `build.zig:36`, `build.zig:38` |
| `zig build check` | Type-checks the daemon without emitting a binary. | `build.zig:213`, `build.zig:227` |
| `zig build wasm` | Builds browser-facing KaguraVox/KaguraVis codec and transport WASM modules. | `build.zig:176`, `build.zig:196`, `build.zig:202` |
| `zig build release` | Builds an optimized stripped daemon with `ReleaseFast`. | `build.zig:230`, `build.zig:244` |

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
