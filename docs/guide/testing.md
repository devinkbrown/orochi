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
| `zig build test-ircx --summary all` | IRCX discovery, PROP, ACCESS/SACCESS, DATA, LISTX, and MODEX paths. |
| `zig build test-event-spine --summary all` | Event spine, IRCX EVENT, observe notes, policy events, and playback paths. |
| `zig build test-mesh --summary all` | Suimyaku mesh, S2S, repair frames, secured links, CONNECT/SQUIT, and mesh projection paths. |
| `zig build test-media --summary all` | Media, DTLS-SRTP, SFU, native media, WebTransport, RTP, and RTCP paths. |
| `zig build test-services --summary all` | Services, account auth, SASL, TOTP, WebAuthn, sessions, Tegami, and successor paths. |
| `zig build test-helix --summary all` | Helix upgrade, migration, resume, capsule, and handoff paths. |
| `zig build test-smoke --summary all` | Inner-loop roadmap gate: `check` plus TLS/server/config focused suites. |
| `zig build test-roadmap --summary all` | Server-roadmap gate: `check` plus server/config/IRCX/event/mesh/services/TLS focused suites. |
| `zig build test-smoke -Doptimize=ReleaseSafe --summary all` | Optimized smoke gate for safety-checked release codegen paths. |

Every focused lane has a `-verbose` twin, for example
`zig build test-tls-verbose --summary all`. Use verbose lanes in CI, tmux, or
any long run where silence looks like a hang; they print each test name before it
executes, include per-test duration, and finish with the slowest tests.

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
| `zig build all-checks --summary all` | Deterministic pre-push gate: `check`, WASM build, full tests, bounded fuzz, and BoGo shim self-tests. |
| `zig build all-checks-verbose --summary all` | Same gate, with per-test progress for the full suite. |

`zig build ct-check` is intentionally separate. It is a timing/statistical
constant-time harness and should not be folded into deterministic CI gates.

## Roadmap-change default

For daemon/TLS/server roadmap work, run:

```sh
zig build test-smoke --summary all
zig build test-roadmap-verbose --summary all
zig build test -Dtest-filter="<feature keyword>" --summary all
zig build test-smoke -Doptimize=ReleaseSafe --summary all
zig build all-checks --summary all
```

When config files changed, also run:

```sh
zig build run -- --check-config etc/orochi.reference.toml
```
