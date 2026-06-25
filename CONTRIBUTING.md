# Contributing to Orochi

Thanks for your interest in Orochi. This document explains how to build, test, and
submit changes.

Orochi is licensed under **AGPL-3.0-or-later**. By contributing, you agree that your
contributions are licensed under the same terms (see [LICENSE](LICENSE)).

## Prerequisites

- **Zig 0.16.0** or newer. The build rejects 32-bit targets; Orochi is 64-bit only
  (x86_64 / aarch64), with a wasm32 browser codec as the sole 32-bit exception.
- A Linux host for the full daemon (the reactor uses `io_uring`). Cross-compilation to
  other targets is supported for non-runtime checks.

## Build and test

```sh
zig build              # build the daemon
zig build check        # fast semantic analysis, no binary
zig build test         # run the full test suite
zig build release      # optimized, stripped ReleaseFast daemon -> zig-out/bin/orochi
zig build run          # run the daemon locally
```

Always run `zig build test` before opening a pull request. If you add or remove source
files, regenerate the package-root import lists:

```sh
./tools/genroots.sh
```

## Code standards

- **Pure Zig, no C interop.** The daemon and its entire substrate — systems library,
  crypto, and TLS — are written from scratch in Zig. Do not introduce C dependencies.
- **No external runtime dependencies.** Prefer in-tree, audited implementations.
- **Immutability and explicit error handling.** Avoid hidden mutation; handle every
  error path; never silently swallow failures.
- **Small, focused files.** Favor cohesive modules over large catch-all files.
- **SPDX headers are required.** Every source and script file must begin with:

  ```zig
  // SPDX-FileCopyrightText: <year> <your name> <your email>
  // SPDX-License-Identifier: AGPL-3.0-or-later
  ```

- **Tests are part of the change.** New behavior needs tests; bug fixes should add a
  regression test. The mesh and crypto layers use deterministic-simulation tests driven
  by an injected clock/network/RNG, so failures replay from a 64-bit seed.

## Commit and pull-request process

1. Branch from `main`.
2. Use conventional-commit style subjects: `feat:`, `fix:`, `refactor:`, `docs:`,
   `test:`, `chore:`, `perf:`, `ci:`.
3. Ensure `zig build test` passes and the tree is formatted (`zig fmt`).
4. Open a pull request describing the change and its testing. Link any related issue.
5. Security-sensitive changes (TLS, crypto, the mesh handshake, authentication) receive
   extra review — call them out explicitly in the description.

## Reporting bugs

Open a GitHub issue with the daemon version (`zig build run -- --version` or the commit
hash), your configuration (with secrets redacted), and clear reproduction steps. For
**security vulnerabilities, do not open a public issue** — see [SECURITY.md](SECURITY.md).
