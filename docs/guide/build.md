# Build guide

*Build, test, and cross-compile the Orochi daemon with Zig.*

Orochi builds with Zig's build system and has no package dependencies in
`build.zig.zon`. Linux builds do not link libc; macOS and BSD targets link libc
only for the platform syscalls that require it.

## Requirements

- Zig `0.17.0-dev.1282+c0f9b51d8` or newer as declared by `build.zig.zon`.
- A 64-bit daemon target. `build.zig` rejects 32-bit daemon builds at configure time.

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
| `zig build test-ircx` | Runs focused IRCX, PROP, ACCESS, DATA, LISTX, MODEX, and SACCESS tests. | `build.zig` |
| `zig build test-event-spine` | Runs focused event-spine, EVENT, observe, and playback tests. | `build.zig` |
| `zig build test-mesh` | Runs focused Suimyaku mesh, S2S, repair, and secured-link tests. | `build.zig` |
| `zig build test-media` | Runs focused media, DTLS-SRTP, SFU, native-media, WebTransport, RTP, and RTCP tests. | `build.zig` |
| `zig build test-services` | Runs focused services, account, SASL, TOTP, WebAuthn, session, and Tegami tests. | `build.zig` |
| `zig build test-helix` | Runs focused Helix upgrade, migration, resume, capsule, and handoff tests. | `build.zig` |
| `zig build test-smoke` | Runs `check` plus focused TLS/server/config suites. | `build.zig` |
| `zig build test-roadmap` | Runs `check` plus focused server roadmap suites. | `build.zig` |
| `zig build all-checks` | Runs deterministic pre-push checks: `check`, WASM build, full tests, bounded fuzz replay, and BoGo shim self-tests. | `build.zig` |
| `zig build test-verbose` | Runs full tests with per-test progress output. | `build.zig` |
| `zig build all-checks-verbose` | Runs deterministic pre-push checks with per-test progress output for the full suite. | `build.zig` |
| `zig build check` | Type-checks the daemon without emitting a binary. | `build.zig` |
| `zig build wasm` | Builds browser-facing KaguraVox/KaguraVis codec and transport WASM modules. | `build.zig` |
| `zig build release` | Builds an optimized stripped daemon with `ReleaseFast`. | `build.zig` |
| `zig build package` | Stages the ReleaseFast daemon, reference config, and systemd unit into the install prefix. | `build.zig` |

`-Dtest-filter=<text>` is a build option. Do not pass `-- --test-filter`; that
does not configure the build graph and can run far more than intended. See the
[testing guide](testing.md) for the recommended lanes.

## Cross targets

Pass `-Dtarget=<triple>` to choose a target; the build script uses Zig's
standard target options.

For example:

```sh
zig build -Dtarget=x86_64-linux
zig build -Dtarget=aarch64-linux -Doptimize=ReleaseSafe
zig build check -Dtarget=x86_64-linux
```

The daemon target must be 64-bit. The `wasm` step is the deliberate
`wasm32-freestanding` exception for browser codec and transport artifacts, not
for the daemon.

## Optimization

Use Zig's standard `-Doptimize=` modes. Debug builds keep symbols; optimized
daemon builds strip debug info.

## Packaging

`zig build package` is the deployable bundle step. It is separate from the default
install so `zig build` stays a fast debug binary install. By default it stages under
`zig-out/`; use `--prefix <dir>` for a release staging directory:

```sh
zig build package --prefix /tmp/orochi-stage
```

The staged layout is:

| Path | Contents |
|---|---|
| `bin/orochi` | ReleaseFast stripped daemon |
| `etc/orochi/orochi.reference.toml` | Annotated reference config |
| `lib/systemd/system/orochi.service` | systemd unit for production deployment |

See the [runbook](../RUNBOOK.md) for install, reload, and rollback procedures.
