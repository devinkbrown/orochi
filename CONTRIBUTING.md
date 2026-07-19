# Contributing to Onyx Server

Onyx Server is a clean-room, Zig-native IRC daemon. Contributions are welcome, but the bar
is intentionally high: changes should keep the daemon source-backed, tested, and
operationally understandable.

Onyx Server is licensed under **AGPL-3.0-or-later**. By contributing, you agree that your
contributions are licensed under the same terms; see [LICENSE](LICENSE).

## Prerequisites

- Zig `0.17.0-dev.1282+c0f9b51d8` or newer, matching `build.zig.zon`.
- A 64-bit target for the daemon. The browser WASM artifacts are the only deliberate
  `wasm32` exception.
- Linux for full runtime testing. The daemon reactor uses `io_uring`; non-Linux
  targets are still useful for semantic/cross-build checks where supported.
- Python 3 for runtime smoke helpers in `tools/`.

## Source Of Truth

Use the current source before trusting older planning notes:

| Need | Source |
|---|---|
| Build/test/deploy commands | `zig build --help`, `build.zig` |
| Config schema | `src/daemon/config_format.zig`, `src/daemon/config_boot.zig`, `etc/onyx-server.reference.toml` |
| Live capability list | `src/daemon/dispatch.zig` |
| Command/module registry | `src/daemon/modules/manifest.zig`, `src/daemon/registry.zig` |
| Server behavior proof | `src/daemon/server.zig` tests and focused build lanes |
| Operator docs | `docs/guide/`, `docs/reference/`, `docs/RUNBOOK.md` |

Planning and research docs are historical design context. If they disagree with live
source, fix the reference/guide docs or the code, not the evidence.

## Build Commands

<!-- AUTO-GENERATED: build-commands -->
| Command | Purpose |
|---|---|
| `zig build` | Build and install the debug daemon to `zig-out/bin/onyx-server`. |
| `zig build check` | Fast semantic analysis without emitting a binary. |
| `zig build test` | Full module plus executable-root test suite. |
| `zig build test-smoke --summary all` | Fast roadmap gate: semantic check plus TLS/server/config suites. |
| `zig build test-roadmap --summary all` | Server-roadmap gate: server/config/IRCX/event/mesh/services/TLS suites. |
| `zig build test-roadmap-verbose --summary all` | Same roadmap gate with per-test progress and slow-test reporting. |
| `zig build test-smoke -Doptimize=ReleaseSafe --summary all` | Optimized smoke gate for safety-checked release codegen paths. |
| `zig build all-checks --summary all` | Deterministic pre-push gate: check, WASM, full tests, bounded fuzz replay, and BoGo shim self-tests. |
| `zig build all-checks-verbose --summary all` | Full deterministic gate with verbose progress for long tmux/CI runs. |
| `zig build release` | Build a stripped ReleaseFast daemon. |
| `zig build package` | Stage ReleaseFast daemon, reference config, and systemd unit into the install prefix. |
<!-- /AUTO-GENERATED: build-commands -->

Use `-Dtest-filter="<substring>"` as a build option for focused work:

```sh
zig build test-mod -Dtest-filter="mTLS:" --summary all
zig build test-exe -Dtest-filter="threaded server:" --summary all
```

Do not pass `-- --test-filter`; it bypasses the build graph filters and can run far
more than intended.

## Runtime Smokes

After building:

```sh
python3 tools/runtime_smoke.py zig-out/bin/onyx-server
python3 tools/upgrade_smoke.py zig-out/bin/onyx-server
```

`runtime_smoke.py` cold-boots a loopback daemon, registers a client, checks PING/PONG,
and quits cleanly. `upgrade_smoke.py` exercises Helix/SIGUSR2 hot-upgrade and verifies
the listener and carried session survive the exec.

## Code Standards

- Pure Zig. Do not add C interop, vendored C shims, or runtime package dependencies.
- Preserve explicit allocator ownership and error handling.
- Keep protocol behavior source-backed and test-backed.
- Add tests with behavior changes. Bug fixes should carry regression tests.
- Prefer focused modules over catch-all files.
- Keep generated root imports current when adding/removing Zig source:

  ```sh
  ./tools/genroots.sh
  ```

- Source and script files need SPDX headers:

  ```zig
  // SPDX-FileCopyrightText: <year> <your name> <your email>
  // SPDX-License-Identifier: AGPL-3.0-or-later
  ```

## Documentation Standards

- Guides and references must document shipped behavior, not aspirational backlog.
- When a doc claims a command, capability, config key, or runtime behavior, ground it
  in current source or a passing test.
- Update `docs/README.md` when adding a new major guide/reference.
- Keep `docs/reference/config.md` and `etc/onyx-server.reference.toml` synchronized when
  config keys change.
- Keep `docs/guide/testing.md` synchronized with `zig build --help`.

## Pull Request Checklist

Before opening or merging a change:

```sh
zig build test-smoke --summary all
zig build test-roadmap --summary all
zig build test-smoke -Doptimize=ReleaseSafe --summary all
zig build all-checks --summary all
git diff --check
```

Also run these when relevant:

```sh
zig build run -- --check-config etc/onyx-server.reference.toml
python3 tools/runtime_smoke.py zig-out/bin/onyx-server
python3 tools/upgrade_smoke.py zig-out/bin/onyx-server
```

For TLS/crypto/S2S/auth changes, explicitly call out the security surface in the PR
description and include the focused lane used to prove it.

## Commit Style

Use conventional-style subjects:

- `feat:`
- `fix:`
- `test:`
- `docs:`
- `ci:`
- `refactor:`
- `perf:`
- `chore:`

Keep commits scoped. Do not mix unrelated roadmap, docs, and mechanical cleanup unless
the change is intentionally a broad synchronization pass.

## Reporting Bugs

Open a GitHub issue with:

- Onyx Server commit hash or VERSION output.
- Zig version.
- Redacted config.
- Reproduction steps.
- Relevant log excerpt.

Do not file public issues for security vulnerabilities. Use [SECURITY.md](SECURITY.md).
