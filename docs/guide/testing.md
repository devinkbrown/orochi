# Testing guide

Orochi's test suite is large, so the build graph exposes several lanes. Use the
smallest lane that proves the change, then run a broader gate before pushing.

## Fast lanes

| Command | Use it for |
|---|---|
| `zig build check` | Fast semantic/type check without emitting a daemon binary. |
| `zig build test-mod -Dtest-filter="<text>" --summary all` | One focused library/module test filter. |
| `zig build test-exe -Dtest-filter="<text>" --summary all` | One focused executable-root test filter. |
| `zig build test-tls --summary all` | Yoroi TLS, mTLS, ECH, RPK, delegated credential, and record-size regressions. |
| `zig build test-server --summary all` | Threaded server, auth, CertFP, and daemon integration regressions. |
| `zig build test-config --summary all` | TOML parser, boot projection, and reference-config regressions. |
| `zig build test-smoke --summary all` | Inner-loop roadmap gate: `check` plus TLS/server/config focused suites. |

Every focused lane has a `-verbose` twin, for example
`zig build test-tls-verbose --summary all`. Use verbose lanes in CI, tmux, or
any long run where silence looks like a hang; they print each test name before it
executes.

Focused filters are build options, not test-binary arguments:

```sh
zig build test -Dtest-filter="mTLS:" --summary all
```

Do not use `zig build test -- --test-filter ...`; that does not configure the
build graph and can accidentally run the broad suite.

## Broad deterministic lanes

| Command | Use it for |
|---|---|
| `zig build test --summary all` | Full module + executable-root tests. |
| `zig build fuzz --summary all` | Bounded replay of coverage-fuzz seed corpora. |
| `zig build bogo-shim-test --summary all` | Self-driven BoGo shim parse/framing/subprocess smokes. |
| `zig build all-checks --summary all` | Deterministic pre-push gate: `check`, full tests, bounded fuzz, and BoGo shim self-tests. |
| `zig build all-checks-verbose --summary all` | Same gate, with per-test progress for the full suite. |

`zig build ct-check` is intentionally separate. It is a timing/statistical
constant-time harness and should not be folded into deterministic CI gates.

## Roadmap-change default

For daemon/TLS/server roadmap work, run:

```sh
zig build test-smoke --summary all
zig build test -Dtest-filter="<feature keyword>" --summary all
zig build all-checks --summary all
```

When config files changed, also run:

```sh
zig build run -- --check-config etc/orochi.reference.toml
```
